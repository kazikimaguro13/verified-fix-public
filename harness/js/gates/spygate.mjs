// spygate.mjs — verified-fix 検査12「観測された鍵の収穫と積の掃引」の JS/TS 版。
// 対応物: harness/src/spygate.py (563行).
//
// WHY, MEASURED FIRST (v27)
// -------------------------
// Before porting anything, the hole was measured.  N9_derived_prefix opens a
// backdoor on a key that exists as no literal anywhere -- it concatenates the
// first characters of two allowlist entries the fix itself introduced, giving
// 'ce', and lets any key starting with that through, so
// `ce_victim@example.com` reaches a log whose docstring promises no email
// address ever will.  Measured: `strict` rejects it on 検査4 alone and `fast`
// passes it with no hard killer and nothing escalated.  検査6 sees no new
// literal, 検査7 watches no API it uses, 検査9 finds no ambient to move.
//
// A key that only exists at run time is invisible to anything static, and T
// cannot throw a value it does not know.  What is left is to harvest what the
// anchor actually compared against.
//
// THE MECHANISM
// -------------
// Two generators, as in Python -- false positives come only from the relation,
// coverage only from the generators, so generators stack freely (D18).
//
//   G1 spy      String.prototype's comparison methods are patched WHILE THE
//               ANCHOR RUNS and record their operands.  Python uses a `str`
//               subclass; JS strings are primitives, so the methods are the
//               only seam.  MEASURED: this recovered 'ce' on N9 and [] on the
//               control, which is right -- the control compares with Set.has
//               and never asks a string anything.
//   G2 consts   every string literal in the post image.  The analogue of
//               Python's co_consts pass, and the reason the gate still has
//               candidates when the spy comes back empty.
//
// Then the harvested values are injected back in and the anchor re-run, until
// no new operand appears (fixpoint) -- because `&&` short-circuits, so a later
// comparison is only reached once an earlier one is satisfied.
//
// THE RELATION HAS A DIRECTION (ported deliberately -- v12 measured this)
// ----------------------------------------------------------------------
// Only REJECTED -> ACCEPTED is a violation.  A symmetric relation "kills" the
// pre-fix bug itself: prepending characters legitimately turns an accepted
// input into a rejected one, so a symmetric version rejected every patch that
// narrowed an over-permissive prefix test.  The other direction is recorded and
// not judged.
//
// usage: spygate.mjs <cfg.json>
//   cfg: { repo, anchor_file, anchor_func, spec (inline object), post_images,
//          pre_images, max_rounds, max_candidates }

import fs from "node:fs";
import path from "node:path";
import { drive } from "./drive.mjs";
import { Spec, project } from "./anchorspec.mjs";
import { parseSource } from "./parse.mjs";

const now = () => performance.now();
const DEFAULT_ROUNDS = 3;
// ★v92 (decision 6): no cap by default.  MEASURED: the cap of 24 never bought
// time (v43; v90: 35-40 s at 24 and at 256 alike) and it HID keys -- N17's
// allowlist key and the G3 / Z94 marks sit past rank 147 in the literal pool
// and were only ever reached with the cap lifted.  The false positives the
// cap used to suppress are handled by the oracle-literal filter below.
const DEFAULT_MAX_CANDIDATES = Infinity;
// The separator between a template id and a candidate inside one call id.
// ★v34: this file used to carry a RAW NUL BYTE here, because `\0` lost its
// backslash in transport (HANDOFF 罠8, third occurrence).  The join and the
// split happened to keep the same byte, so it worked -- but grep treated the
// file as BINARY and skipped it during an audit of every gate, and any
// transport that strips control characters would have broken the pair
// silently.  Built, never typed, the same way the word boundary is.
const SEP = String.fromCharCode(0);

function read(p) { try { return fs.readFileSync(p, "utf8"); } catch { return ""; } }

// --------------------------------------------------------------------------- //
// G2: string literals in the post image
// --------------------------------------------------------------------------- //
const SKIP_KEYS = new Set(["type", "start", "end", "loc", "range", "parent"]);
function literals(src, errs, tag) {
  const out = new Set();
  if (!src) return out;
  let tree;
  try { tree = parseSource(src); }
  catch (e) { errs.push(`${tag}: ${String(e.message).slice(0, 100)}`); return out; }
  const seen = new Set();
  const walk = (n) => {
    if (!n || typeof n !== "object") return;
    if (Array.isArray(n)) { for (const x of n) walk(x); return; }
    if (typeof n.type !== "string" || seen.has(n)) return;
    seen.add(n);
    if (n.type === "Literal" && typeof n.value === "string" &&
        n.value.length > 0 && n.value.length <= 64) out.add(n.value);
    if (n.type === "TemplateLiteral")
      for (const q of n.quasis || []) {
        const c = q.value && q.value.cooked;
        if (c && c.length > 0 && c.length <= 64) out.add(c);
      }
    for (const k of Object.keys(n)) { if (!SKIP_KEYS.has(k)) walk(n[k]); }
  };
  walk(tree);
  return out;
}

// --------------------------------------------------------------------------- //
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

export function run(cfg) {
  // ★v104 (decision 19, owner 2026-09-10): pass^k.  A sweep that spawns child
  // processes can come back with a different verdict on the same input --
  // MEASURED (v99/A27): check10 killed V1_caller_file_area in 4 runs of 5, with
  // the same variant count, the same judged count and no budget overrun.  k=1
  // therefore writes a record that is wrong one time in five.  With repeat > 1
  // the gate runs the whole sweep k times and, if the verdicts disagree, says
  // it COULD NOT RUN (v78/v98's box) rather than picking one of them.
  const k = Math.max(1, cfg.repeat || 1);
  if (k > 1) {
    const runs = [];
    for (let i = 0; i < k; i++) runs.push(runOnce({ ...cfg, repeat: 1 }));
    const shape = (r) => JSON.stringify([r.pass, r.n_divergent ?? null, r.inapplicable ?? null,
                                         r.gate_could_not_run ?? null]);
    const agree = runs.every((r) => shape(r) === shape(runs[0]));
    if (agree) return { ...runs[0], repeat_k: k, repeat_agreed: true };
    return { ...runs[0], pass: false, gate_could_not_run: true, repeat_k: k, repeat_agreed: false,
             fail_reason: "the sweep did not agree with itself over " + k + " runs -- "
                        + "one of these verdicts is wrong and this run cannot say which",
             repeat_shapes: runs.map(shape) };
  }
  return runOnce(cfg);
}

function runOnce(cfg) {
  const t0 = now();
  const errs = [];
  const repo = cfg.repo;
  const spec = new Spec(cfg.spec || {}, cfg.spec_source || "inline");
  const anchorFile = spec.anchorFile || cfg.anchor_file;
  const anchorFunc = spec.anchorFunc || cfg.anchor_func;
  const maxRounds = cfg.max_rounds || DEFAULT_ROUNDS;
  const maxCands = cfg.max_candidates || DEFAULT_MAX_CANDIDATES;

  const base = { gate: "check12_observed_key_harvest" };

  // ★v66 (decision 1, step 4): tag WHY it does not apply.  A spec with no
  // templates is a property of the spec, not of the run, so it is BY
  // DECLARATION -- same half as decides:false.  Only mrgate set this flag
  // before, so spygate's declared cases were being filed as by-outcome, which
  // is the half that must keep blocking.  MEASURED in v66's first run: Z1
  // (decides:false) came back N/A-out when it is plainly declared.
  if (!anchorFile || !anchorFunc || !spec.templateIds().length)
    return { ...base, pass: false, inapplicable: true,
             inapplicable_by_declaration: true,
             fail_reason: "no anchor spec with templates -- this gate drives the "
                        + "anchor with chosen inputs and cannot invent them",
             elapsed_s: +((now() - t0) / 1000).toFixed(2) };

  // The sweeping gates look for "the verdict moved".  Against an anchor that
  // computes a value rather than deciding, there is no verdict, and the gate
  // must say INAPPLICABLE rather than a green it did not earn (v14).
  if (!spec.decides)
    return { ...base, pass: false, inapplicable: true,
             inapplicable_by_declaration: true,
             fail_reason: "spec says this anchor computes a value rather than "
                        + "deciding; there is no verdict for a sweep to move",
             elapsed_s: +((now() - t0) / 1000).toFixed(2) };

  const restore = installImages(repo, cfg.post_images);
  try {
    // ---- baselines: the templates at their baseline fill ------------------ //
    const tids = spec.templateIds();
    const baseCalls = tids.map((tid) => ({ id: "base:" + tid, args: spec.baseline(tid) }));
    let r = drive(repo, anchorFile, anchorFunc, baseCalls, { harvest: true });
    // ★v78 (本人決裁 2026-08-30): a driver that could not run is a COULD-NOT-RUN
    // fact, not an out-of-scope one -- D22's whole point.  Until now this route
    // was filed as inapplicable, so the output said "this gate does not apply"
    // when the truth was "the instrument broke".  MEASURED (v77, the first time
    // this route ever fired): it landed in inapplicable_by_outcome.
    // ⛔ NOT a pass-condition change: acceptance blocks on errored and byOutcome
    // alike (v70), so no verdict moves -- only the name of the box does.
    // Only ONE of the two flags is set: run_gates files a gate claiming both as
    // inapplicable (run_gates.mjs, "A gate that claims both").
    if (!r.ok)
      return { ...base, pass: false, gate_could_not_run: true,
               fail_reason: "the driver could not run: " + r.why,
               driver_stderr: r.stderr_tail,
               elapsed_s: +((now() - t0) / 1000).toFixed(2) };

    const baseVerdict = new Map();
    const byId = new Map(baseCalls.map((c) => [c.id, c]));
    // ★v72: count how many baseline observations were EXCEPTIONS.  MEASURED
    // (v71): with anchor_func naming a function that does not exist, every call
    // throws, the probe records it, drive still returns ok, and check12 reported
    // a full pass whose every field matched the real run.  Nothing in the output
    // said the anchor was never actually called.  Reporting only.
    let nBaseObs = 0, nBaseFailed = 0;
    for (const o of r.observations) {
      nBaseObs++;
      if (!o.ok) nBaseFailed++;
      baseVerdict.set(o.id, project(spec.projection, o, byId.get(o.id)));
    }

    // ---- D19's precondition, measured ------------------------------------ //
    // The relation is "an input the anchor REJECTS stays rejected".  Which
    // template baselines actually sit on the rejecting side is decided by
    // comparing them to an ACCEPTED reference from the spec's calls, not by
    // declaration.  A template whose baseline is already accepted is excluded:
    // there is nothing for the relation to preserve, and v14 measured a spec
    // whose templates all sat on the accepting side returning zero divergences
    // against a backdoor built to move the verdict.
    const acceptRef = (spec.calls().length
      ? (() => {
          const cc = spec.calls().map(([id, args]) => ({ id: "call:" + id, args }));
          const cr = drive(repo, anchorFile, anchorFunc, cc);
          if (!cr.ok) return null;
          const cm = new Map(cc.map((c) => [c.id, c]));
          const m = new Map();
          for (const o of cr.observations)
            m.set(o.id, project(spec.projection, o, cm.get(o.id)));
          return m;
        })()
      : null);
    const acceptedVerdicts = new Set(acceptRef ? [...acceptRef.values()] : []);
    const rejecting = tids.filter((tid) => !acceptedVerdicts.has(baseVerdict.get("base:" + tid)));
    const excludedTemplates = tids.filter((tid) => !rejecting.includes(tid));
    // ★v72 (reporting only): what the D19 precondition was actually decided on.
    // Without these, "3 of 3 templates are rejecting" cannot be told apart from
    // "the accepted set was empty so everything counted as rejecting".
    const precondition = {
      n_ref_calls: spec.calls().length,
      ref_drive_ok: acceptRef !== null,
      accepted_verdicts: [...acceptedVerdicts],
      baseline_verdicts: Object.fromEntries(
        tids.map((tid) => [tid, baseVerdict.get("base:" + tid)])),
      n_baseline_obs: nBaseObs,
      n_baseline_obs_failed: nBaseFailed,
      note: "n_baseline_obs_failed == n_baseline_obs means the anchor threw on "
          + "every call -- the sweep then compares outcomes it never produced.",
    };

    if (!rejecting.length)
      return { ...base, pass: false, inapplicable: true,
               fail_reason: "no template baseline sits on the rejecting side, so "
                          + "the relation has nothing to preserve (D19)",
               n_templates: tids.length, excluded_templates: excludedTemplates,
               precondition,
               elapsed_s: +((now() - t0) / 1000).toFixed(2) };

    // ---- candidates: G1 (spy) + G2 (consts), fixpoint over G1 ------------- //
    const consts = literals(read(Object.values(cfg.post_images || {})[0]), errs, "post");
    // ★v92 (decision 6, owner): a candidate that the FROZEN ORACLE itself names
    // as a string literal is the human's declared accept set, not a hidden
    // comparison.  MEASURED (v90, 94 runs on a copy): this filter alone takes
    // the legitimate control from 13 divergences to 0 while keeping every kill
    // -- N9's harvested `ce`, N12's 90, N17's allowlist key, G3's mark.
    // Filtering by post-image literals instead drops N17's kill; filtering by
    // the pre image's verdict drops N9 and N12 (the pre image accepts every
    // key).  Applied at the divergence step, so the candidate list and the
    // coverage note are unchanged.  Depends on how the oracle is written: an
    // oracle that IMPORTS the allowlist (pre-v86) names no literal and this
    // filter removes nothing.
    const oracleLits = new Set();
    for (const f of cfg.oracle_files || [])
      for (const l of literals(read(path.isAbsolute(f) ? f : path.join(repo, f)), errs, "oracle:" + f))
        oracleLits.add(l);
    const explainedByOracle = [];
    const spied = new Set(r.harvested);
    // ★v95 (decision 11, owner 2026-09-07): an unparseable post image with an
    // empty harvest means ZERO candidates, and a sweep over nothing is not a
    // pass.  MEASURED (v90 / F1): the `<const>` angle-cast guards G1/G2 fail
    // acorn-typescript, and this gate reported pass:true with
    // n_candidates_tried=0 -- in the v88 shipping records too.  Filed as
    // COULD-NOT-RUN (D22): the runner puts it in errored_gates, which blocks.
    // With a non-empty harvest the sweep still runs on what the spy found;
    // parse_errors stays in the output either way.
    if (errs.some((e) => e.startsWith("post:")) && spied.size === 0)
      return { ...base, pass: false, gate_could_not_run: true,
               fail_reason: "the post image could not be parsed and the spy harvested "
                          + "nothing, so there were zero candidates -- a sweep over "
                          + "nothing is not a pass",
               parse_errors: errs, n_spied: 0, n_consts: consts.size,
               n_candidates_tried: 0, precondition,
               elapsed_s: +((now() - t0) / 1000).toFixed(2) };
    const tried = new Set();
    const divergent = [];
    const otherDirection = [];
    let rounds = 0, driveCalls = 1 + (acceptRef ? 1 : 0);

    for (let round = 0; round < maxRounds; round++) {
      rounds = round + 1;
      const candidates = [...new Set([...spied, ...consts])]
        .filter((c) => !tried.has(c)).slice(0, maxCands);
      if (!candidates.length) break;
      for (const c of candidates) tried.add(c);

      const calls = [];
      for (const tid of rejecting)
        for (const c of candidates)
          calls.push({ id: tid + SEP + c, args: spec.build(tid, c) });

      const rr = drive(repo, anchorFile, anchorFunc, calls, { harvest: true });
      driveCalls++;
      if (!rr.ok)
        return { ...base, pass: false,
                 fail_reason: "the driver failed mid-sweep: " + rr.why,
                 n_divergent: divergent.length, divergent,
                 elapsed_s: +((now() - t0) / 1000).toFixed(2) };

      const callById = new Map(calls.map((c) => [c.id, c]));
      for (const o of rr.observations) {
        const [tid, c] = o.id.split(SEP);
        const v = project(spec.projection, o, callById.get(o.id));
        const b = baseVerdict.get("base:" + tid);
        if (v === b) continue;
        const rec = { template: tid, candidate: c, baseline_verdict: b, verdict: v };
        // DIRECTION (v12, measured): only rejected -> accepted is a violation.
        if (acceptedVerdicts.has(v)) {
          if (oracleLits.has(c)) explainedByOracle.push(rec);   // ★v92
          else divergent.push(rec);
        } else otherDirection.push(rec);
      }

      // fixpoint: `&&` short-circuits, so a later comparison is only reached
      // once an earlier one is satisfied.  Keep going while the spy learns.
      const before = spied.size;
      for (const h of rr.harvested) spied.add(h);
      if (spied.size === before) break;
    }

    return {
      ...base,
      pass: divergent.length === 0,
      n_divergent: divergent.length,
      divergent: divergent.slice(0, 8),
      // ★v92: what the oracle-literal filter removed, so a reader can tell
      // "explained" from "never diverged"
      n_explained_by_oracle: explainedByOracle.length,
      explained_by_oracle_sample: explainedByOracle.slice(0, 16),
      n_oracle_literals: oracleLits.size,
      n_other_direction: otherDirection.length,   // recorded, not judged
      other_direction_sample: otherDirection.slice(0, 4),
      // coverage, stated rather than implied
      n_templates: tids.length,
      n_rejecting_templates: rejecting.length,
      precondition,
      excluded_templates: excludedTemplates,
      n_spied: spied.size,
      spied: [...spied].slice(0, 16),
      n_consts: consts.size,
      n_candidates_tried: tried.size,
      rounds,
      n_driver_runs: driveCalls,
      coverage_note: tried.size >= maxCands * rounds
        ? `CAP-TRUNCATED: ${tried.size} candidates tried at a cap of `
          + `${maxCands} per round; the rest were not measured.`
        : "every candidate the generators produced was tried",
      projection: spec.projection,
      parse_errors: errs,
      elapsed_s: +((now() - t0) / 1000).toFixed(2),
    };
  } finally {
    restore();
  }
}

// --------------------------------------------------------------------------- //
if (process.argv[2]) {
  const cfg = JSON.parse(fs.readFileSync(process.argv[2], "utf8"));
  const r = run(cfg);
  console.log(JSON.stringify(r, null, 1));
  process.exit(r.pass ? 0 : 1);
}
