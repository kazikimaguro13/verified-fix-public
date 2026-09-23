// gate_power.mjs — ゲートの `pass` に力があるかを測る道具（v46・DESIGN D24）
//
// ⛔ THIS IS NOT A GATE.  It has no number, it is never called by run_gates.mjs,
//    and no verdict anywhere depends on what it prints.  D24 論点8: giving a
//    number to something that does not take part in the verdict brings back the
//    confusion D22 exists to prevent.
//
// THE QUESTION
// ------------
//   When a gate says `pass`, is that "looked and found nothing wrong" or
//   "could not see it"?
//
// WHY IT EXISTS (measured, v44 §2-a)
// ----------------------------------
//   検査5 was wired to `S5_refactor` and answered `pass`.  Measuring that pass by
//   hand showed HALF of it was empty: a POST image that really did change the
//   request body (visible only through the injected `fetchImpl`) produced ZERO
//   divergences and the same `pass` (PWR1), while a POST image that changed the
//   return value produced a type divergence and FAIL (PWR2).
//   ⇒ "no difference within what can be observed" is not "behaviour unchanged".
//   §0-c is the discipline "do not use 'not measured' in place of 'nothing
//   wrong'".  This tool applies it to a gate's own `pass`.
//
// WHAT IT DOES (D24 の9論点そのまま)
// ----------------------------------
//   1. take the mutants Stryker generates ON THE LINES THE PATCH CHANGED
//      (`--mutate` ranges from `git diff -U0` vs `refs/vf/pre/<id>`; the SAME
//      mechanism 検査4 uses -- `mutgate.mjs` is invoked, never edited)   [論点1]
//   2. apply them to the POST image ONE AT A TIME
//   3. RUN THE GATE ITSELF and record its pass/fail                      [論点3]
//      ⚠ Stryker's own verdict is NOT used.  Two reasons, both measured:
//        (a) v42: a `static` mutant is filed "Survived" although the mutant
//            switch is never taken -- it was never executed.
//        (b) Stryker's verdict answers "did the TEST SUITE notice", and the
//            question here is "did THIS GATE notice".
//   4. asymmetric cost: "has power" needs ONE mutant (stop early); "vacuous"
//      needs ALL of them.  → full scan with early exit.                  [論点4]
//   5. ALWAYS print the counts.  "was vacuous" and "stopped early" must never
//      wear the same shape (§0-c, 論点4)
//   6. ALWAYS print the generator.  The claim this tool can support is
//      "has power over what StrykerJS generates", never "sees any edit".  [論点7]
//
// WHAT IT DELIBERATELY DOES NOT DO
// --------------------------------
//   - it does not join the pipeline and does not touch `run_gates.mjs`   [論点6]
//   - it does not enter any gate's pass condition
//   - it does not decide whether a `survived` should become `inapplicable`.
//     That is a design judgement and a human makes it.  This prints material.
//
// SELF-CHECK (§0-c: a measuring instrument that measures nothing prints 0)
// -----------------------------------------------------------------------
//   `--positive-control rel=abs` installs an image that is KNOWN to change
//   observable behaviour and runs the gate on it before the mutants.  If the
//   gate passes that too, the plumbing is what is blind, not the corpus, and
//   every `blind` row below is meaningless.  Say so and stop.
//
// ★v139 (A7-r 1 + A7-r 2, 2026-09-22).  TWO changes, both inside this tool.
//   A7-r 1  観測面: GATE_RUNNERS carried ONE entry (検査5), so every number this
//           tool has ever printed is about one gate.  D24 論点5 named 検査5・8・
//           9・12 as the gates whose `pass` is read as a guarantee.  The other
//           three are added below, each one mirroring the argv/cfg that
//           run_gates.mjs builds for it, and each one reading the verdict out of
//           the gate's JSON -- never out of an exit code (§0-c / v98 決定13).
//   A7-r 2  生成器: StrykerJS skips `X as const` subtrees whole
//           (instrumenter/util/syntax-helpers.js isTypeNode ->
//            tsTypeAnnotationNodeTypes -> babel-transformer.js shouldSkip),
//           measured in v46 (§0-j-9 ④).  Every allow-list in the repository
//           under test is written `[...] as const`, so this tool has never
//           mutated one.  v50/v54's method is applied here too: blank every
//           `as T` / `as const` / `satisfies T` / `<T>x` with SPACES OF THE SAME
//           LENGTH -- `as` is erased before anything runs, and length-preserving
//           blanking leaves every line and column unchanged, so the position map
//           back to the real source is the IDENTITY -- let Stryker generate
//           against the blanked copy over the SAME --mutate ranges, and apply
//           the new mutants to the REAL source.
//           ⛔ 検査4's own as-const pass (mutgate.mjs §12-A17) writes the FIRST
//           pass's report back before it exits, so none of it reaches this tool.
//           This is a second, independent pass; it JUDGES nothing, it only
//           enlarges the population the gates are measured against.
//
// usage:
//   node gate_power.mjs <orch2 cfg.json> [options]
//     --gate <name>              which gate to measure: check5 / check8 /
//                                check9 / check12 (D24 論点5 の順).
//                                GATE_RUNNERS below is the one place another
//                                one gets added.
//     --gates <dir>              where the gate .mjs files live
//     --report <path>            reuse an existing Stryker report
//     --no-run                   do not invoke mutgate.mjs (needs --report)
//     --no-asconst               skip the `as const` generator pass (A7-r 2)
//     --mutants-out <path>       write the generated population to a cache
//     --mutants-in <path>        read the population from that cache instead of
//                                generating it again, so the four gates of one
//                                entry share ONE generation
//     --positive-control rel=abs an image known to be observable (self-check)
//     --no-early-stop            keep going after the first catch
//     --max-mutants <n>          cap; sets cap_hit and truncates coverage
//     --timeout-s <n>            per gate run (default 300)
//     --out <path>               write the whole result as JSON
import fs from "node:fs";
import path from "node:path";
import { createRequire } from "node:module";
import { spawnSync } from "node:child_process";
import { pathToFileURL } from "node:url";
import { JS_GATES_DIR } from "./vf_paths.mjs";

// --------------------------------------------------------------------------- //
// args
// --------------------------------------------------------------------------- //
function opt(flag, dflt = null) {
  const i = process.argv.indexOf(flag);
  return i > 0 && i + 1 < process.argv.length ? process.argv[i + 1] : dflt;
}
const has = (flag) => process.argv.includes(flag);

const cfgPath = process.argv[2];
if (!cfgPath || cfgPath.startsWith("--")) {
  console.error("usage: node gate_power.mjs <cfg.json> [--gate check5] [--gates D] "
              + "[--report F] [--no-run] [--positive-control rel=abs] "
              + "[--no-early-stop] [--max-mutants N] [--timeout-s N] [--out F]");
  process.exit(2);
}
const cfg = JSON.parse(fs.readFileSync(cfgPath, "utf8"));
const repo = cfg.repo;
// ★v134 (judgement 61): JS_GATES_DIR honours VF_GATES first, then
// JS_GATES_DIR, then $VF_HOME/jsharness/gates -- see tools/vf_paths.mjs.
const GATES = opt("--gates", JS_GATES_DIR);
const gateName = opt("--gate", "check5");
const earlyStop = !has("--no-early-stop");
const maxMutants = +opt("--max-mutants", "0") || 0;
const timeoutMs = (+opt("--timeout-s", "300") || 300) * 1000;
const reportFile = opt("--report", path.join(repo, "reports/mutation.json"));

const positive = {};
{
  const pc = opt("--positive-control");
  if (pc) {
    const j = pc.indexOf("=");
    if (j < 0) { console.error("--positive-control wants rel=abs"); process.exit(2); }
    positive[pc.slice(0, j)] = pc.slice(j + 1);
  }
}

// --------------------------------------------------------------------------- //
// gate runners.  ONE function per gate: given the images currently installed in
// the tree, run that gate and return its raw JSON.  D24 論点5 says 検査5 first;
// 検査8/9/12 are the ones worth adding next (their `pass` is also read as a
// guarantee).  Adding one is a single entry here -- nothing else in this file
// needs to know about it.
// --------------------------------------------------------------------------- //
// ★v139: the three gates added below write their cfg into the SAME scratch
// directory run_gates.mjs uses (v110 決定33: a cfg inside the repository under
// test is the audit's own design document handed to the code being audited --
// `M8_audit_dir` read it and blinded 検査9 completely).  The basename is
// prefixed so this tool never overwrites a cfg a pipeline run is holding.
// 検査5 is LEFT EXACTLY AS IT WAS (its cfg still goes to <repo>/.vf/).
const { scratchPath } = await import(
  pathToFileURL(path.join(GATES, "scratch.mjs")).href);

/** Run a gate CLI and read its verdict out of its JSON.  ⛔ never out of the
 *  exit code: v96/v98 决定13 measured a crashed diffgate being filed as the
 *  hard killer `check5`.  A gate whose output cannot be read COULD NOT RUN. */
function runGateJson(gateFile, cfgAbs, cfgObj) {
  fs.mkdirSync(path.dirname(cfgAbs), { recursive: true });
  fs.writeFileSync(cfgAbs, JSON.stringify(cfgObj), "utf8");
  const r = spawnSync(process.execPath, [path.join(GATES, gateFile), cfgAbs],
    { cwd: repo, encoding: "utf8", maxBuffer: 64 * 1024 * 1024, timeout: timeoutMs });
  if (r.error && r.error.code === "ETIMEDOUT")
    return { gate_could_not_run: true, pass: null,
             reason: "gate timed out after " + (timeoutMs / 1000) + "s" };
  try { return JSON.parse(r.stdout); }
  catch {
    return { gate_could_not_run: true, pass: null,
             reason: "gate produced no parseable JSON",
             exit_code: r.status,
             stdout_tail: String(r.stdout || "").split("\n").slice(-6).join(" | "),
             stderr_tail: String(r.stderr || "").split("\n").slice(-6).join(" | ") };
  }
}
const cannotRun = (why) => ({ gate_could_not_run: true, pass: null, reason: why });
const readSpec = () => JSON.parse(fs.readFileSync(cfg.anchor_spec, "utf8"));

/** D22 / §0-c.  Some of these gates return `pass: true` together with a
 *  `skipped` string or `inapplicable_by_measurement`, i.e. a green they did not
 *  earn by looking (mrgate: "anchor file not in patch", "every template
 *  abstained").  For a POWER measurement those are the single most dangerous
 *  shape there is: a gate that never swept would be counted as a gate that
 *  swept and saw nothing.  Re-file them as COULD-NOT-RUN. */
function earnedOrNot(r) {
  if (r && r.pass === true && (r.skipped || r.inapplicable_by_measurement === true))
    return { ...r, pass: null, gate_could_not_run: true,
             reason: "the gate returned pass WITHOUT looking: "
                   + String(r.skipped || "inapplicable_by_measurement") };
  return r;
}

const GATE_RUNNERS = {
  check5(postImages) {
    if (!cfg.anchor_spec) {
      // §0-c / D22.  "no anchor spec" is NOT "the gate looked and saw nothing".
      return { gate_could_not_run: true, pass: null,
               reason: "cfg has no anchor_spec; 検査5's spec mode has no corpus "
                     + "to drive, so this variant cannot be measured with 検査5" };
    }
    const dgCfg = path.join(repo, ".vf/gate_power.diffgate.cfg.json");
    fs.mkdirSync(path.dirname(dgCfg), { recursive: true });
    fs.writeFileSync(dgCfg, JSON.stringify({
      repo, anchor_file: cfg.anchor_file, anchor_func: cfg.anchor_func,
      spec: JSON.parse(fs.readFileSync(cfg.anchor_spec, "utf8")),
      spec_source: cfg.anchor_spec,
      pre_images: cfg.pre_images, post_images: postImages,
    }), "utf8");
    const r = spawnSync(process.execPath, [path.join(GATES, "diffgate.mjs"), dgCfg],
      { cwd: repo, encoding: "utf8", maxBuffer: 64 * 1024 * 1024, timeout: timeoutMs });
    if (r.error && r.error.code === "ETIMEDOUT")
      return { gate_could_not_run: true, pass: null,
               reason: "gate timed out after " + (timeoutMs / 1000) + "s" };
    try { return JSON.parse(r.stdout); }
    catch {
      return { gate_could_not_run: true, pass: null,
               reason: "gate produced no parseable JSON",
               exit_code: r.status,
               stdout_tail: String(r.stdout || "").split("\n").slice(-6).join(" | "),
               stderr_tail: String(r.stderr || "").split("\n").slice(-6).join(" | ") };
    }
  },

  // ---- 検査8: metamorphic equivalence-class sweep (mrgate.mjs) ------------ //
  // run_gates.mjs:820-831.  Same keys, same defaults (max_cp 0x110000,
  // precond_max_cp 0x800), same spec object read from cfg.anchor_spec.
  check8(postImages) {
    if (!cfg.anchor_spec)
      return cannotRun("cfg has no anchor_spec; 検査8 sweeps the code-point axis "
                     + "of a spec template and must not invent one");
    return earnedOrNot(runGateJson("mrgate.mjs",
      scratchPath(repo, "gate_power.mrgate.cfg.json"), {
        repo, anchor_file: cfg.anchor_file, anchor_func: cfg.anchor_func,
        spec: readSpec(), spec_source: cfg.anchor_spec,
        pre_images: cfg.pre_images, post_images: postImages,
        max_cp: cfg.mr_max_cp || 0x110000,
        precond_max_cp: cfg.mr_precond_max_cp || 0x800,
      }));
  },

  // ---- 検査9: ambient invariance (ambgate.mjs) --------------------------- //
  // run_gates.mjs:744-756.  This is the one gate here that needs no anchor
  // spec: its observable IS the oracle's verdict.  `vitest_bin` is the v127
  // 決定48 key; run_gates passes the binary IT is using, and the default is
  // the literal ambgate already had.
  check9(postImages) {
    if (!(cfg.oracle_files || []).length)
      return cannotRun("cfg names no oracle file; 検査9's observable IS the "
                     + "oracle's verdict, so it cannot run without one");
    return earnedOrNot(runGateJson("ambgate.mjs",
      scratchPath(repo, "gate_power.ambgate.cfg.json"), {
        repo, pre_images: cfg.pre_images, post_images: postImages,
        oracle_files: cfg.oracle_files || [],
        vitest_bin: cfg.vitest_bin || "node_modules/vitest/vitest.mjs",
        amb_budget_s: cfg.amb_budget_s || 30,
      }));
  },

  // ---- 検査12: observed-key harvest (spygate.mjs) ------------------------ //
  // run_gates.mjs:775-787.  `max_candidates` is deliberately `undefined` when
  // the cfg does not set it -- v92 決定6 removed the default cap, and writing a
  // number here would silently re-introduce it.
  check12(postImages) {
    if (!cfg.anchor_spec)
      return cannotRun("cfg has no anchor_spec; 検査12 drives the anchor with "
                     + "chosen inputs and must not invent them");
    return earnedOrNot(runGateJson("spygate.mjs",
      scratchPath(repo, "gate_power.spygate.cfg.json"), {
        repo, anchor_file: cfg.anchor_file, anchor_func: cfg.anchor_func,
        spec: readSpec(), spec_source: cfg.anchor_spec,
        pre_images: cfg.pre_images, post_images: postImages,
        max_rounds: cfg.spy_rounds || 3,
        max_candidates: cfg.spy_candidates || undefined,
        oracle_files: cfg.oracle_files || [],
      }));
  },
};
if (!GATE_RUNNERS[gateName]) {
  console.error("★ unknown gate: " + gateName
              + "  (known: " + Object.keys(GATE_RUNNERS).join(", ") + ")");
  process.exit(2);
}

// The three conditions 検査5's `pass` is the conjunction of.  Naming them is how
// a caught mutant says WHICH part of the gate saw it.
const CAUGHT_FIELDS = {
  check5: [["out_of_scope_divergences", "n"], ["return_type_divergences", "n"],
           ["uncovered_changed_functions", "len"]],
  // ★v139.  Each list is exactly the set of counters that gate's own `pass`
  // expression reads, taken from the gate's source, so a caught mutant says
  // WHICH part of the gate saw it:
  //   mrgate.mjs:301   pass = violations === 0 && candViol.length === 0
  //   ambgate.mjs:378  pass = divergent.length === 0
  //   spygate.mjs:343  pass = divergent.length === 0
  check8: [["n_divergent_total", "n"], ["n_candidate_violations", "n"]],
  check9: [["n_divergent", "n"]],
  check12: [["n_divergent", "n"]],
};
// Reported by the gate, never judged by it.  A mutant that moves ONLY these is
// visible to the gate and yet passes -- which is a different thing from blind,
// and it is exactly the material §12-A9 needs.  ⛔ never folded into n_caught.
const SEEN_NOT_JUDGED_FIELDS = {
  check5: [["in_scope_divergences", "n"], ["emitted_divergences", "n"]],
  // ★v139.  Each of these is a number the gate prints and its `pass` does not
  // read -- the gate saw the mutant move something and still passed.
  //   check8  n_other_direction / n_candidate_other_direction: a divergence
  //           that does NOT land on the accepted side (mrgate.mjs:322 "recorded,
  //           not judged" -- the direction restriction is v12's measurement)
  //   check9  n_settings_excluded_by_precondition: a divergence disqualified
  //           because the unpatched anchor moves under the same ambient (D19)
  //   check12 n_other_direction (spygate.mjs:351 "recorded, not judged") and
  //           n_explained_by_oracle (a divergence the oracle-literal filter
  //           removed, v92 決定10)
  check8: [["n_other_direction", "n"], ["n_candidate_other_direction", "n"]],
  check9: [["n_settings_excluded_by_precondition", "n"]],
  check12: [["n_other_direction", "n"], ["n_explained_by_oracle", "n"]],
};
function fieldsThatFired(res, table) {
  const out = [];
  for (const [name, kind] of (table[gateName] || [])) {
    const v = res[name];
    const n = kind === "len" ? (Array.isArray(v) ? v.length : 0) : (+v || 0);
    if (n > 0) out.push(name + "=" + n);
  }
  return out;
}
// ★v46 measured this the hard way: comparing only the COUNTS of the
// reported-but-not-judged fields made every S1_control mutant look motionless,
// because the baseline already reported `emitted_divergences=2` and each mutant
// also reported exactly 2 -- different content, same number.  A count is not a
// fingerprint.  Fold in the samples the gate prints.
//
// ⚠ THE SAMPLES ARE TRUNCATED BY THE GATE (emitted_sample <= 4,
//   in_scope_sample <= 6).  So a DIFFERENCE here is evidence that the mutant
//   moved something the gate sees; SAMENESS IS NOT evidence that it moved
//   nothing.  §0-c: name which direction the silence runs.
const NOT_JUDGED_SAMPLES = {
  check5: ["emitted_sample", "in_scope_sample"],
  // ★v139.  Same warning, one gate further: check8 prints NO untruncated
  // sample of the not-judged side, so its fingerprint is COUNTS ONLY and is
  // the weakest of the four.  Said here rather than left to be inferred.
  check8: [],
  check9: ["excluded_sample", "axes_no_observable_effect"],
  check12: ["other_direction_sample"],
};
function notJudgedFingerprint(res) {
  const parts = fieldsThatFired(res, SEEN_NOT_JUDGED_FIELDS);
  for (const f of (NOT_JUDGED_SAMPLES[gateName] || []))
    parts.push(f + "=" + JSON.stringify(res[f] || []));
  return parts.join("|");
}

// --------------------------------------------------------------------------- //
// image installation (same shape as run_gates.mjs installImages / run_check5)
// --------------------------------------------------------------------------- //
const treeSaved = new Map();          // abs -> original text (or null = absent)
function installOne(rel, srcAbsOrText, isText = false) {
  const dst = path.join(repo, rel);
  if (!treeSaved.has(dst))
    treeSaved.set(dst, fs.existsSync(dst) ? fs.readFileSync(dst, "utf8") : null);
  if (isText) fs.writeFileSync(dst, srcAbsOrText, "utf8");
  else fs.copyFileSync(srcAbsOrText, dst);
}
function restoreTree() {
  for (const [dst, prev] of treeSaved) {
    if (prev === null) fs.rmSync(dst, { force: true });
    else fs.writeFileSync(dst, prev, "utf8");
  }
}

/** stryker json schema 1.0 positions are 1-origin line / 1-origin column. */
function offsetOf(src, line, column) {
  let off = 0;
  for (let i = 1; i < line; i++) {
    const nl = src.indexOf("\n", off);
    if (nl < 0) return -1;
    off = nl + 1;
  }
  return off + (column - 1);
}

// --------------------------------------------------------------------------- //
// ★v139 (A7-r 2) — mutants from INSIDE `as const`
// --------------------------------------------------------------------------- //
// StrykerJS files `TSAsExpression` as a type node and skips the subtree, so the
// allow-list that IS the substance of several of these patches has never had a
// mutant generated in it (v46 §0-j-9 ④, measured in Stryker's own source).
// v50's method, unchanged: blank the type side of every `as` / `satisfies` /
// `<T>x` with spaces of the SAME LENGTH, generate against the blanked copy over
// the SAME ranges, and splice the result into the REAL text.  Because blanking
// preserves length, the position map is the identity -- and that is CHECKED,
// three times, not assumed.
//
// ⛔ WHAT THIS DOES NOT DO: it does not judge anything.  Stryker's verdict on
// these is not read (it is not read for the ordinary ones either); they are only
// added to the population each gate is then run against, one at a time.
// FAIL-SAFE DIRECTION: every check below refuses on the safe side.  If anything
// fails to verify, zero mutants are added and the population is exactly what it
// was before this block existed.
const NLC = String.fromCharCode(10);
const TABC = String.fromCharCode(9);
const flatten = (s) => s.split("")
  .map((c) => (c === NLC || c === TABC ? " " : c)).join("").trim().slice(0, 40);

function asConstMutants(mutateSpec, oracleFiles, firstReportBytes) {
  const AC = {
    attempted: false, ok: false, reason: null,
    n_regions: 0, n_regions_in_mutate_range: 0, n_new_mutants: 0,
    n_unmappable: 0, unmappable: [], sites: [],
    same_length: null, all_diffs_inside_spans: null, parse_errors: null,
    stryker_s: 0, files: {}, mutants: [],
  };
  try {
    if (!mutateSpec || !mutateSpec.length) {
      AC.reason = "no --mutate range was handed over (検査4 was not run, or it "
                + "produced none), so there is no range to generate into";
      return AC;
    }
    const ranges = [];
    for (const s of mutateSpec) {
      const m = /^(.*):(\d+)-(\d+)$/.exec(s);
      if (m) ranges.push({ file: m[1], lo: +m[2], hi: +m[3] });
    }
    if (!ranges.length) {
      AC.reason = "the --mutate spec could not be parsed: " + mutateSpec.join(",");
      return AC;
    }
    const req = createRequire(path.join(repo, "package.json"));
    const ts = req("typescript");
    const orig = {};            // rel -> the REAL (post-image) text on disk
    const blankedText = {};     // rel -> the blanked copy, same byte length
    let sitesInRange = 0;
    for (const relSpec of [...new Set(ranges.map((r) => r.file))]) {
      const abs = path.join(repo, relSpec);
      if (!fs.existsSync(abs)) continue;
      const text = fs.readFileSync(abs, "utf8");
      orig[relSpec] = text;
      const sf = ts.createSourceFile(relSpec, text, ts.ScriptTarget.Latest, true,
        relSpec.endsWith("x") ? ts.ScriptKind.TSX : ts.ScriptKind.TS);
      const spans = [];
      (function walk(node) {
        // `X as T` / `X as const` / `X satisfies T`: the type sits between the
        // end of the operand and the end of the node.
        if (ts.isAsExpression(node)
            || (ts.isSatisfiesExpression && ts.isSatisfiesExpression(node)))
          spans.push([node.expression.end, node.end]);
        // `<T>x`: the type sits between the start of the node and the operand.
        else if (ts.isTypeAssertionExpression && ts.isTypeAssertionExpression(node))
          spans.push([node.getStart(sf), node.expression.getStart(sf)]);
        ts.forEachChild(node, walk);
      })(sf);
      AC.n_regions += spans.length;
      if (!spans.length) continue;
      const chars = text.split("");
      for (const [a, b] of spans)
        for (let i = a; i < b; i++) if (chars[i] !== NLC) chars[i] = " ";
      const blanked = chars.join("");
      // ★検算 (a): same byte length, every difference inside a blanked span,
      //            and the blanked copy still parses.
      const sameLen = blanked.length === text.length;
      let inSpan = true;
      for (let i = 0; i < Math.min(blanked.length, text.length); i++)
        if (blanked[i] !== text[i] && !spans.some(([a, b]) => i >= a && i < b))
          inSpan = false;
      const diag = ts.createSourceFile(relSpec, blanked, ts.ScriptTarget.Latest,
        true, ts.ScriptKind.TS).parseDiagnostics || [];
      AC.same_length = AC.same_length === false ? false : sameLen;
      AC.all_diffs_inside_spans = AC.all_diffs_inside_spans === false ? false : inSpan;
      AC.parse_errors = (AC.parse_errors || 0) + diag.length;
      for (const [a, b] of spans) {
        const lo = text.slice(0, a).split(NLC).length;
        const hi = text.slice(0, b).split(NLC).length;
        const hit = ranges.some((x) => relSpec.endsWith(x.file) && !(hi < x.lo || lo > x.hi));
        if (hit) sitesInRange++;
        AC.sites.push({ file: relSpec, line: lo, in_mutate_range: hit,
                        text: flatten(text.slice(a, b)) });
      }
      if (!sameLen || !inSpan || diag.length) continue;
      blankedText[relSpec] = blanked;
    }
    AC.n_regions_in_mutate_range = sitesInRange;

    if (AC.same_length === false || AC.all_diffs_inside_spans === false || AC.parse_errors) {
      AC.reason = "the blanked copy did not verify (same_length=" + AC.same_length
                + " diffs_inside_spans=" + AC.all_diffs_inside_spans
                + " parse_errors=" + AC.parse_errors + ") -- refusing to generate "
                + "against a text whose positions may not map back";
      return AC;
    }
    if (!Object.keys(blankedText).length) {
      AC.reason = "no `as` / `satisfies` / `<T>x` assertion in the changed files";
      return AC;
    }
    if (sitesInRange === 0) {
      AC.reason = "every assertion lies OUTSIDE the --mutate ranges, so blanking "
                + "them cannot produce a mutant on a line the patch changed";
      return AC;
    }
    AC.attempted = true;

    const firstRep = JSON.parse(firstReportBytes.toString("utf8"));
    const mkey = (file, m) => file + ":" + m.location.start.line + ":"
               + m.location.start.column + ":" + m.mutatorName + ":" + String(m.replacement);
    const before = new Set();
    for (const [file, f] of Object.entries(firstRep.files || {}))
      for (const m of f.mutants || []) before.add(mkey(file, m));

    // ---- second Stryker pass, on the blanked copy, the SAME ranges -------- //
    // Same argv mutgate.mjs builds (mutgate.mjs:160-166) and the same PATH fix
    // (v29: npx resolves `node` from PATH, and Stryker 10 needs >= 22).
    for (const [rel, txt] of Object.entries(blankedText)) installOne(rel, txt, true);
    fs.rmSync(reportFile, { force: true });
    const nodeDir = path.dirname(process.execPath);
    const env = { ...process.env,
                  PATH: nodeDir + path.delimiter + (process.env.PATH || "") };
    const args = ["stryker", "run",
      "--mutate", mutateSpec.join(","),
      "--testFiles", (oracleFiles || []).join(","),
      "--coverageAnalysis", "perTest",
      "--reporters", "json,clear-text",
      "--logLevel", "warn", "--allowEmpty"];
    const s0 = Date.now();
    const r2 = spawnSync("npx", args, { cwd: repo, encoding: "utf8", env });
    AC.stryker_s = +((Date.now() - s0) / 1000).toFixed(2);
    const afterRep = fs.existsSync(reportFile)
      ? JSON.parse(fs.readFileSync(reportFile, "utf8")) : null;
    // ★from here on the disk carries the REAL source again, and the report file
    //   is the FIRST pass's bytes -- nothing downstream may see the blanked run.
    for (const [rel, txt] of Object.entries(orig)) installOne(rel, txt, true);
    fs.writeFileSync(reportFile, firstReportBytes);
    if (!afterRep) {
      AC.reason = "Stryker produced no report on the blanked copy (rc=" + r2.status
                + ") -- the population is exactly the first pass's";
      AC.attempted = false;
      AC.stderr_tail = String(r2.stderr || "").split("\n").slice(-6).join(" | ");
      return AC;
    }
    for (const [file, f] of Object.entries(afterRep.files || {})) {
      const rel = Object.keys(orig).find((k) => file.endsWith(k));
      if (!rel || blankedText[rel] === undefined) continue;
      const blanked = blankedText[rel];
      const text = orig[rel];
      for (const m of f.mutants || []) {
        if (before.has(mkey(file, m))) continue;          // not new: not ours
        const line = m.location.start.line;
        if (!ranges.some((x) => file.endsWith(x.file) && line >= x.lo && line <= x.hi))
          continue;                                       // outside every range
        const a = offsetOf(blanked, m.location.start.line, m.location.start.column);
        const b = offsetOf(blanked, m.location.end.line, m.location.end.column);
        if (a < 0 || b < 0 || b < a) {
          AC.n_unmappable++;
          AC.unmappable.push(rel + ":" + line + " " + m.mutatorName + " -- span out of range");
          continue;
        }
        // ★検算 (b): the span must name the SAME TEXT in both copies.  If it
        // does not, the location is inside a blanked region and names text that
        // does not exist in the real source.  Counted, never silently dropped.
        if (blanked.slice(a, b) !== text.slice(a, b)) {
          AC.n_unmappable++;
          AC.unmappable.push(rel + ":" + line + " " + m.mutatorName
            + " -- the span overlaps a blanked assertion region");
          continue;
        }
        AC.mutants.push({ ...m, file: rel, from_as_const: true });
      }
    }
    AC.n_new_mutants = AC.mutants.length;
    AC.files = orig;
    AC.ok = true;
    return AC;
  } catch (e) {
    AC.reason = "the asconst stage threw: " + ((e && e.message) || String(e));
    AC.attempted = false; AC.ok = false; AC.mutants = [];
    return AC;
  }
}

const basePost = { ...(cfg.post_images || {}) };
// under .vf/ because that directory is already the harness' scratch space in
// this repo; a temp dir at the repo root gets swept up by tool globs.
fs.mkdirSync(path.join(repo, ".vf"), { recursive: true });
const tmpDir = fs.mkdtempSync(path.join(repo, ".vf", "gate_power-"));

let result = null;
let fatal = null;
try {
  for (const [rel, src] of Object.entries(basePost)) installOne(rel, src);

  // ------------------------------------------------------------------------- //
  // 1. mutant generation.  検査4 と同じ仕組み: mutgate.mjs invoked as-is.
  // ------------------------------------------------------------------------- //
  const files = {};
  const mutants = [];
  let mutgateOut = null;
  let AC = { attempted: false, ok: false, n_new_mutants: 0,
             reason: "the `as const` pass did not run" };
  const mutantsIn = opt("--mutants-in");
  const mutantsOut = opt("--mutants-out");

  if (mutantsIn && fs.existsSync(mutantsIn)) {
    // ★v139: the four gates of one entry are measured against ONE population.
    // Regenerating it per gate costs two Stryker runs each time and -- worse --
    // could hand different gates different mutants, which would make the table
    // below a comparison of four different measurements.
    const cache = JSON.parse(fs.readFileSync(mutantsIn, "utf8"));
    for (const [rel, src] of Object.entries(cache.files || {})) {
      const abs = path.join(repo, rel);
      const onDisk = fs.existsSync(abs) ? fs.readFileSync(abs, "utf8") : null;
      files[rel] = { source: src, abs, sameBytes: onDisk !== null && onDisk === src };
    }
    for (const m of cache.mutants || []) mutants.push(m);
    mutgateOut = cache.mutgate_out || null;
    AC = cache.asconst || AC;
    console.error("# 変異はキャッシュから: " + mutantsIn + "  ("
      + mutants.length + " 件, うち as const 由来 "
      + mutants.filter((m) => m.from_as_const).length + " 件)");
  } else {
    if (!has("--no-run")) {
      const args = [path.join(GATES, "mutgate.mjs"), repo,
                    cfg.base_ref || "HEAD", (cfg.oracle_files || []).join(",")];
      console.error("# 変異の生成: " + args.join(" "));
      const r = spawnSync(process.execPath, args,
        { cwd: repo, encoding: "utf8", maxBuffer: 64 * 1024 * 1024 });
      // 検査4 exits non-zero whenever it FAILS, which is normal here.  What
      // matters is the report file, not the exit code (判定は終了コードで取らない
      // — ただしここでは判定を取っていない。生成だけである).
      try { mutgateOut = JSON.parse(r.stdout); } catch { mutgateOut = null; }
    }
    if (!fs.existsSync(reportFile))
      throw new Error("Stryker report が無い: " + reportFile
                    + "  (--report で指すか --no-run を外す)");
    const firstReportBytes = fs.readFileSync(reportFile);
    const rep = JSON.parse(firstReportBytes.toString("utf8"));

    // ----------------------------------------------------------------------- //
    // 2. the text the mutants were located against MUST be the text on disk.
    //    (mutant_triage.mjs learned this the hard way: line/col are coordinates
    //    into `files[rel].source`, so a stale report splices somewhere else.)
    // ----------------------------------------------------------------------- //
    for (const [rel, fd] of Object.entries(rep.files || {})) {
      const abs = path.join(repo, rel);
      const onDisk = fs.existsSync(abs) ? fs.readFileSync(abs, "utf8") : null;
      files[rel] = { source: fd.source, abs, sameBytes: onDisk !== null && onDisk === fd.source };
      for (const m of fd.mutants || []) mutants.push({ ...m, file: rel, from_as_const: false });
    }
    const badFiles = Object.entries(files).filter(([, v]) => !v.sameBytes).map(([r]) => r);
    if (badFiles.length)
      throw new Error("測定不能: Stryker が変異させた本文と、いま disk にある本文が違う: "
                    + badFiles.join(", ") + "  (report を作り直すこと)");

    // ---- ★v139 / A7-r 2: the generator's blind spot ----------------------- //
    if (!has("--no-asconst")) {
      AC = asConstMutants(mutgateOut ? (mutgateOut.mutate_spec || null) : null,
                          cfg.oracle_files || [], firstReportBytes);
      if (AC.ok) {
        for (const [rel, text] of Object.entries(AC.files || {})) {
          if (files[rel]) continue;    // already carried by the first pass
          files[rel] = { source: text, abs: path.join(repo, rel), sameBytes: true };
        }
        for (const m of AC.mutants) mutants.push(m);
      }
      console.error("# as const の中: 領域 " + AC.n_regions
        + "（範囲内 " + AC.n_regions_in_mutate_range + "）→ 新しい変異 "
        + AC.n_new_mutants + " 件"
        + (AC.n_unmappable ? "・写像できず " + AC.n_unmappable + " 件" : "")
        + (AC.reason ? "  " + AC.reason : ""));
    } else {
      AC.reason = "--no-asconst";
    }
    if (mutantsOut) {
      const cacheFiles = {};
      for (const [rel, v] of Object.entries(files)) cacheFiles[rel] = v.source;
      fs.writeFileSync(mutantsOut, JSON.stringify({
        variant: cfg.name, base_ref: cfg.base_ref || "HEAD",
        files: cacheFiles, mutants, mutgate_out: mutgateOut,
        asconst: { ...AC, files: undefined, mutants: undefined },
      }), "utf8");
    }
  }
  {
    const badFiles = Object.entries(files).filter(([, v]) => !v.sameBytes).map(([r]) => r);
    if (badFiles.length)
      throw new Error("測定不能: 変異を位置づけた本文と、いま disk にある本文が違う: "
                    + badFiles.join(", ") + "  (生成をやり直すこと)");
  }
  const nFromAsConst = mutants.filter((m) => m.from_as_const === true).length;

  const mutatorHist = {};
  const strykerStatusHist = {};
  for (const m of mutants) {
    mutatorHist[m.mutatorName] = (mutatorHist[m.mutatorName] || 0) + 1;
    strykerStatusHist[m.status] = (strykerStatusHist[m.status] || 0) + 1;
  }
  const generator = {
    name: "StrykerJS",
    version: (() => {
      try {
        return JSON.parse(fs.readFileSync(
          path.join(repo, "node_modules/@stryker-mutator/core/package.json"), "utf8")).version;
      } catch { return null; }
    })(),
    scope: "--mutate mutation-range (file:start-end) from `git diff -U0 --relative "
         + (cfg.base_ref || "HEAD") + " -- src`  （検査4 と同じ範囲）",
    mutate_spec: mutgateOut ? (mutgateOut.mutate_spec || null) : null,
    mutators: mutatorHist,
    // printed so nobody has to wonder whether it was used.  IT WAS NOT.
    stryker_status_histogram: strykerStatusHist,
    stryker_verdict_used: false,
    stryker_verdict_why_not:
      "v42 measured that a `static` mutant is filed Survived although its switch "
      + "is never taken, and Stryker's verdict answers 'did the test suite "
      + "notice', not 'did this gate notice'.",
    // ★v139 / A7-r 2 — the second pass, and what it cost
    n_from_as_const: nFromAsConst,
    asconst: AC,
  };
  const scopeNote =
    "力があると出ても、それは「" + generator.name + " が上の範囲で生成する変異について"
    + "力がある」であって「あらゆる改変を見られる」ではない（D24 論点7）。"
    + "★v139: 生成器は2本になった — Stryker の素の走査と、`as const` の型側を"
    + "同じ長さの空白で塗り潰した写しに対する2本目の走査（"
    + nFromAsConst + " 件がそこから来た）。それでも「あらゆる改変」ではない。";

  // ------------------------------------------------------------------------- //
  // 3. baseline — the gate on the UNMUTATED post image
  // ------------------------------------------------------------------------- //
  const t0 = Date.now();
  const baseRes = GATE_RUNNERS[gateName](basePost);
  const baseline = {
    pass: baseRes.pass, could_not_run: baseRes.gate_could_not_run === true,
    inapplicable: baseRes.inapplicable === true,
    reason: baseRes.reason || baseRes.fail_reason || null,
    compared_calls: baseRes.compared_calls ?? null,
    caught_fields: fieldsThatFired(baseRes, CAUGHT_FIELDS),
    seen_not_judged: fieldsThatFired(baseRes, SEEN_NOT_JUDGED_FIELDS),
    not_judged_fingerprint: notJudgedFingerprint(baseRes),
    elapsed_s: baseRes.elapsed_s ?? null,
  };
  console.error("# baseline: " + gateName + "="
    + (baseline.could_not_run ? "COULD-NOT-RUN" : baseline.inapplicable ? "INAPPLICABLE"
       : baseline.pass ? "pass" : "FAIL")
    + (baseline.reason ? "  " + baseline.reason.slice(0, 90) : ""));

  // A power measurement presupposes that the gate PASSES on the unmutated post.
  // If it already fails, every mutant fails too and `n_caught` would be a number
  // about nothing.  Say that instead of printing it.
  const measurable = baseline.pass === true;

  // ------------------------------------------------------------------------- //
  // 4. self-check: an image known to be observable must be caught
  // ------------------------------------------------------------------------- //
  let selfcheck = null;
  if (Object.keys(positive).length) {
    const post = { ...basePost, ...positive };
    for (const [rel, src] of Object.entries(positive)) installOne(rel, src);
    const r = GATE_RUNNERS[gateName](post);
    for (const [rel, src] of Object.entries(basePost)) installOne(rel, src);
    selfcheck = {
      images: positive, pass: r.pass,
      could_not_run: r.gate_could_not_run === true,
      caught_fields: fieldsThatFired(r, CAUGHT_FIELDS),
      seen_not_judged: fieldsThatFired(r, SEEN_NOT_JUDGED_FIELDS),
      ok: r.pass === false && r.gate_could_not_run !== true,
    };
    console.error("# selfcheck: " + (selfcheck.ok
      ? "OK（観測できると分かっている改変をゲートが捕まえた: "
        + selfcheck.caught_fields.join(",") + "）"
      : "★BROKEN（観測できるはずの改変にもゲートが pass。以下の blind は無意味）"));
  }

  // ------------------------------------------------------------------------- //
  // 5. the scan
  // ------------------------------------------------------------------------- //
  const rows = [];
  let nCaught = 0, nBlind = 0, nErrored = 0, nSpliceFailed = 0, nSeenNotJudged = 0;
  let stoppedEarly = false, capHit = false;
  // ★v139: `--max-mutants` takes the head of the report order, and the
  // `as const` mutants are APPENDED, so a plain cap would drop exactly the
  // population A7-r 2 exists to look at -- a cap that silently answers the
  // opposite question.  `--max-mutants-per-class N` caps the two classes
  // separately and keeps each one's report order.  With the flag absent the
  // order and the limit are byte-for-byte what they were.
  let order = mutants.slice();            // report order; deterministic
  const perClass = +opt("--max-mutants-per-class", "0") || 0;
  if (perClass > 0) {
    const ordinary = order.filter((m) => m.from_as_const !== true).slice(0, perClass);
    const asconst = order.filter((m) => m.from_as_const === true).slice(0, perClass);
    order = ordinary.concat(asconst);
  }
  const limit = maxMutants > 0 ? Math.min(maxMutants, order.length) : order.length;

  // (offsetOf now lives at module level -- the `as const` pass needs it too.)

  if (measurable) {
    for (let i = 0; i < limit; i++) {
      const m = order[i];
      const f = files[m.file];
      const a = offsetOf(f.source, m.location.start.line, m.location.start.column);
      const b = offsetOf(f.source, m.location.end.line, m.location.end.column);
      if (a < 0 || b < 0 || b < a) {
        nSpliceFailed++;
        rows.push({ id: m.id, file: m.file, line: m.location.start.line,
                    mutator: m.mutatorName, from_as_const: m.from_as_const === true,
                    verdict: "SPLICE-FAILED" });
        continue;
      }
      const mutated = f.source.slice(0, a) + m.replacement + f.source.slice(b);
      // sanity: the splice must actually change the text (§0-c -- a "mutant"
      // that is byte-identical to the original tests nothing).
      if (mutated === f.source) {
        nSpliceFailed++;
        rows.push({ id: m.id, file: m.file, line: m.location.start.line,
                    mutator: m.mutatorName, from_as_const: m.from_as_const === true,
                    verdict: "NO-OP-SPLICE" });
        continue;
      }
      const tmpImage = path.join(tmpDir, "m" + m.id + "_" + path.basename(m.file));
      fs.writeFileSync(tmpImage, mutated, "utf8");
      installOne(m.file, mutated, true);
      const post = Object.prototype.hasOwnProperty.call(basePost, m.file)
        ? { ...basePost, [m.file]: tmpImage } : basePost;
      const r = GATE_RUNNERS[gateName](post);
      // restore this file to the unmutated post image before the next round
      if (Object.prototype.hasOwnProperty.call(basePost, m.file))
        installOne(m.file, basePost[m.file]);
      else installOne(m.file, f.source, true);

      const errored = r.gate_could_not_run === true || r.inapplicable === true
                   || r.pass === null || r.pass === undefined;
      const caughtFields = fieldsThatFired(r, CAUGHT_FIELDS);
      const seen = fieldsThatFired(r, SEEN_NOT_JUDGED_FIELDS);
      let verdict;
      if (errored) { nErrored++; verdict = "ERROR"; }        // D22: NOT a catch
      else if (r.pass === false) { nCaught++; verdict = "CAUGHT"; }
      else {
        nBlind++;
        // did it move anything the gate reports but does not judge?
        const moved = notJudgedFingerprint(r) !== baseline.not_judged_fingerprint;
        if (moved) { nSeenNotJudged++; verdict = "BLIND(見えてはいる)"; }
        else verdict = "BLIND";
      }
      rows.push({ id: m.id, file: m.file, line: m.location.start.line,
                  mutator: m.mutatorName, from_as_const: m.from_as_const === true,
                  original: f.source.slice(a, b).slice(0, 60),
                  replacement: String(m.replacement).slice(0, 60),
                  stryker_status: m.status, static: m.static,
                  gate_pass: r.pass, caught_by: caughtFields,
                  seen_not_judged: seen,
                  compared_calls: r.compared_calls ?? null,
                  gate_reason: errored ? (r.reason || r.fail_reason || null) : null,
                  elapsed_s: r.elapsed_s ?? null, verdict });
      console.error("  [" + (i + 1) + "/" + limit + "] " + m.id + " "
                  + m.mutatorName + " L" + m.location.start.line + " -> " + verdict
                  + (caughtFields.length ? " (" + caughtFields.join(",") + ")" : "")
                  + (seen.length ? " [報告のみ: " + seen.join(",") + "]" : ""));
      if (earlyStop && verdict === "CAUGHT") { stoppedEarly = i + 1 < order.length; break; }
    }
    capHit = !stoppedEarly
      && ((maxMutants > 0 && maxMutants < mutants.length)
          || (perClass > 0 && order.length < mutants.length));
  }

  const nTried = rows.length;
  // ------------------------------------------------------------------------- //
  // 6. verdict.  D24 論点2 ①: 空虚判定は「気づいた変異が 0 か否か」の二値。
  //    ⛔ 「生存ゼロ」（論点2 ②・選択肢B の解禁条件）とは別物なので混ぜない。
  // ------------------------------------------------------------------------- //
  let verdict, verdictWhy;
  if (!measurable) {
    verdict = "NOT_MEASURED";
    verdictWhy = baseline.could_not_run
      ? "ゲートが走れなかった（" + (baseline.reason || "理由不明") + "）。"
        + "『力が無い』ではない。"
      : baseline.inapplicable
      ? "ゲートが inapplicable と答えた（比較0件）。『力が無い』ではない。"
      : "変異を当てる前からゲートが FAIL している（"
        + baseline.caught_fields.join(",") + "）。"
        + "この状態で『変異で落ちた』を数えても、それは変異について何も言わない。";
  } else if (selfcheck && selfcheck.ok === false) {
    verdict = "NOT_MEASURED";
    verdictWhy = "自己検査が壊れている。観測できると分かっている改変にもゲートが pass "
               + "したので、下の blind は道具の側の沈黙と区別できない。";
  } else if (nCaught > 0) {
    verdict = "HAS_POWER";
    verdictWhy = nTried + " 件目で気づいた。1件で言えるので早期終了した（D24 論点4）。";
  } else if (capHit || nTried < mutants.length) {
    verdict = "NOT_MEASURED";
    verdictWhy = "全件を当てていない（" + nTried + "/" + mutants.length + " 件）。"
               + "『空虚』は全件でしか言えない（D24 論点4）。";
  } else if (mutants.length === 0) {
    verdict = "NOT_MEASURED";
    verdictWhy = "パッチの変更行から変異が1件も生成されなかった。"
               + "測っていないので『空虚』とは言わない（§0-c）。";
  } else {
    verdict = "VACUOUS";
    verdictWhy = "生成された " + mutants.length + " 件すべてを当てて、ゲートは1件も "
               + "気づかなかった。" + (nErrored ? "（うち " + nErrored
               + " 件はゲートが走れず、気づいたとは数えていない）" : "");
  }

  result = {
    tool: "gate_power", is_a_gate: false, contributes_to_verdict: false,
    design: "DESIGN.md D24",
    variant: cfg.name, repo, gate: gateName,
    base_ref: cfg.base_ref || "HEAD",
    anchor_spec: cfg.anchor_spec || null,
    generator, scope_note: scopeNote,
    baseline, selfcheck,
    // ★件数（§0-c: 「空虚だった」と「途中でやめた」を混ぜない）
    n_mutants_total: mutants.length,
    // ★v139 / A7-r 2: how much of the population only exists because the
    // `as const` subtrees were opened.  Zero here means the generator's blind
    // spot had nothing in it FOR THIS ENTRY -- not that the pass did not run
    // (generator.asconst.reason says which).
    n_mutants_from_as_const: nFromAsConst,
    n_caught_from_as_const: rows.filter((r) => r.from_as_const && r.verdict === "CAUGHT").length,
    n_blind_from_as_const: rows.filter((r) => r.from_as_const
      && String(r.verdict).startsWith("BLIND")).length,
    n_tried: nTried,
    n_caught: nCaught,
    n_blind: nBlind,
    n_errored: nErrored,
    n_splice_failed: nSpliceFailed,
    n_blind_but_observed: nSeenNotJudged,
    blind_but_observed_note:
      "『ゲートは見ているが判定に使っていない』件数。差が出たら動いた証拠になるが、"
    + "ゲートの出す標本は打ち切られている（検査5: emitted_sample<=4 / "
    + "in_scope_sample<=6、検査8 は判定しない側の標本を出さないので件数のみ）ので、"
    + "差が出なかったことは『動いていない』の証拠にはならない（§0-c・A7-r 4）。",
    stopped_early: stoppedEarly,
    cap_hit: capHit,
    max_mutants_per_class: perClass || null,
    n_in_scan_order: order.length,
    coverage_note: nTried >= mutants.length
      ? "every mutant the generator produced was tried"
      : (stoppedEarly ? "EARLY-STOP after the first catch (D24 論点4)"
                      : "TRUNCATED -- not every mutant was tried"),
    verdict, verdict_why: verdictWhy,
    mutants: rows,
    // ★the population, printed even when NOTHING was tried.  §0-c: a run that
    // measured nothing still has to say what it had in front of it -- otherwise
    // "not measured" and "there was nothing there" wear the same shape.
    mutant_inventory: mutants.map((m) => ({
      id: m.id, file: m.file, line: m.location.start.line,
      mutator: m.mutatorName, replacement: String(m.replacement).slice(0, 60),
      stryker_status: m.status, static: m.static,
      from_as_const: m.from_as_const === true,
    })),
    elapsed_s: +((Date.now() - t0) / 1000).toFixed(2),
  };
} catch (e) {
  // §0-c / D22: a tool that could not measure must not print a number that
  // looks like a measurement.
  fatal = String((e && e.stack) || e);
} finally {
  restoreTree();
  fs.rmSync(tmpDir, { recursive: true, force: true });
}
if (!result) {
  const err = { tool: "gate_power", is_a_gate: false, variant: cfg.name,
                gate: gateName, tool_could_not_run: true, verdict: "NOT_MEASURED",
                verdict_why: "道具自身が走れなかった。ゲートの力についても、"
                           + "力が無いことについても、何も言っていない。",
                error: fatal };
  const o = opt("--out");
  if (o) fs.writeFileSync(o, JSON.stringify(err, null, 1), "utf8");
  console.log(JSON.stringify(err, null, 1));
  console.error(cfg.name + "  gate=" + gateName + "  TOOL-COULD-NOT-RUN");
  process.exit(2);
}

// did the restore actually take?  (§0-c: do not count a restore you did not check)
const dirty = [];
for (const [dst, prev] of treeSaved) {
  const now = fs.existsSync(dst) ? fs.readFileSync(dst, "utf8") : null;
  if (now !== prev) dirty.push(path.relative(repo, dst));
}
if (result) result.tree_restored = dirty.length === 0;
if (dirty.length) console.error("★戻し損ね: " + dirty.join(", ") + " — 手で戻すこと");

const text = JSON.stringify(result, null, 1);
const out = opt("--out");
if (out) fs.writeFileSync(out, text, "utf8");
console.log(text);
console.error(`${result.variant}  gate=${result.gate}  ${result.verdict}`
  + `  total=${result.n_mutants_total}(asconst=${result.n_mutants_from_as_const})`
  + ` tried=${result.n_tried}`
  + ` caught=${result.n_caught} blind=${result.n_blind} errored=${result.n_errored}`
  + ` early=${result.stopped_early}`
  + `  generator=${result.generator.name}${result.generator.version ? "@" + result.generator.version : ""}`);
// ⛔ exit code carries NO verdict about the patch.  0 = the measurement ran.
process.exit(dirty.length ? 3 : 0);
