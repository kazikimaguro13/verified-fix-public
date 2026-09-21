// mrgate.mjs — verified-fix 検査8「メタモルフィック等価類スイープ」の JS/TS 版。
// 対応物: harness/src/mrgate.py (283行).
//
// WHY, MEASURED FIRST (v29)
// -------------------------
// N10_codepoint_class puts the backdoor in a REGEX LITERAL over a non-ASCII
// range.  Measured against the ten JS gates before this file existed:
//
//   strict   killed_by ["check4"] only, escalated []
//   fast     killed_by [],         escalated []   -- ACCEPTED
//
// Every static gate is blind to it by construction, and the measurements say so
// rather than the design claiming it:
//   検査6  litgate.mjs:158 excludes regex literals (`!("regex" in node)`), and
//          the patch adds no new string or numeric literal.  n_unexplained 0.
//   検査12 G1 patches String.prototype's comparison methods; RegExp.prototype
//          .test is not one, so the anchor never asks a string anything --
//          MEASURED n_spied 0.  G2 collects string literals only.
//   検査7/9 nothing ambient is read.
//
// THE RELATION
// ------------
// Rather than asking WHICH characters are interesting -- the move that was
// broken at its own boundary three times running -- fix an equivalence class
// and require the verdict to be constant across it:
//
//     two inputs that must receive the same verdict, must receive the same one
//
// Take a template whose baseline the anchor REJECTS and substitute the hole
// with every code point in 0x0000..0x10FFFF.  It is still not a member of the
// allowlist, so the verdict must not move.  An exhaustive sweep of a bounded
// axis HAS NO BOUNDARY TO BE ATTACKED AT: any predicate whose key is "there
// exists a character with property P" is hit, whatever P is, whether or not
// anyone wrote P down.
//
// WHAT IT DOES NOT REACH (stated up front, as in the Python original)
//   * keys that need two or more specific characters AT ONCE
//   * keys on an axis that is not the character axis -- arity, the call stack,
//     the identity of the argument object, ambient module state (検査7/9)
//   * keys whose density is low enough to miss -- but the sweep is exhaustive
//     per class, so a SINGLE-character key of any density is caught outright
//
// THE PRECONDITION IS MEASURED, NOT DECLARED (v14, ported deliberately)
// --------------------------------------------------------------------
// Whether the relation holds at all is a property of WHY the anchor rejects.
// An anchor that rejects the empty string rejects it BECAUSE it is empty, and
// substituting a character is exactly the operation that stops it being empty:
// measured on the Python side, a reject-side template diverged on 201 of 2,048
// code points against the CORRECT implementation, and fired identically against
// a real backdoor -- the gate cannot tell those apart.  So the relation is run
// against the PRE image first, over a cheap prefix, and a template that is
// already violated there ABSTAINS.  A gate must not report a green it did not
// earn, and it must not report a red it cannot justify either.
//
// usage: mrgate.mjs <cfg.json>
//   cfg: { repo, anchor_file, anchor_func, spec, post_images, pre_images,
//          max_cp?, precond_max_cp? }

import fs from "node:fs";
import path from "node:path";
import { sweepAxis } from "./drive.mjs";
import { Spec } from "./anchorspec.mjs";
import { candidatesFrom } from "./regexgen.mjs";
import { parseSource } from "./parse.mjs";

const now = () => performance.now();
// v30: the gate reported ~2.4s MORE elapsed than its own process lived, twice,
// as a FIXED offset rather than a rate.  A process cannot outlive itself, so one
// of the two clocks is being read wrong.  Report both and let the run say which.
const wall = () => Date.now();
const MAX_CP = 0x110000;          // 1,114,112 -- surrogates included
const PRECOND_MAX_CP = 0x800;     // a relation false for an anchor is false early
const CAP = 200;

const OUT_OF_SCOPE =
  "anchor is declared not to return a decision (spec.decides = false), so "
  + "there is no verdict for this relation to hold constant";

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

const secs = (t0) => +((now() - t0) / 1000).toFixed(2);

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
    const shape = (r) => JSON.stringify([r.pass, r.n_divergent_total ?? null, r.inapplicable ?? null,
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
  const w0 = wall();
  const repo = cfg.repo;
  const spec = new Spec(cfg.spec || {}, cfg.spec_source || "inline");
  const anchorFile = spec.anchorFile || cfg.anchor_file;
  const anchorFunc = spec.anchorFunc || cfg.anchor_func;
  const maxCp = cfg.max_cp || MAX_CP;
  const precondMaxCp = Math.min(cfg.precond_max_cp || PRECOND_MAX_CP, maxCp);
  const gatesDir = path.dirname(new URL(import.meta.url).pathname);
  const base = { gate: "check8_metamorphic", anchor: anchorFile, max_cp: maxCp };

  // ---- MISCONFIGURED: the gate should apply and its inputs do not fit ----- //
  // Fail closed.  This is a different thing from OUT OF SCOPE below and the
  // two must not be collapsed into one green (v13/v14).
  if (!anchorFile || !anchorFunc || !spec.templateIds().length)
    return { ...base, pass: false, inapplicable: true,
             fail_reason: "no anchor spec with templates -- this gate sweeps "
                        + "the code-point axis of a template and cannot invent one",
             elapsed_s: secs(t0) };

  // ★v78 (本人決裁 2026-08-30): a spec naming a file that does not exist used
  // to fall through to the out-of-scope green below.  MEASURED (v77): with
  // anchor.file set to a path that does not resolve, this gate returned
  // pass:true with skipped:"anchor file not in patch", and that output was
  // IDENTICAL -- same keys, same values -- to the legitimate case of a real
  // file the patch does not touch.  A typo in a spec path was invisible here.
  // Same unearned-green shape v66 closed for decides:false, at another door.
  // Blast radius at the time of the change: 0 (all four shipping specs name a
  // real file, and all 30 cfgs using them carry its post_image).
  if (!fs.existsSync(path.join(repo, anchorFile)))
    return { ...base, pass: false, inapplicable: true,
             fail_reason: "the spec's anchor file does not exist in the repo: "
                        + anchorFile + " -- this is a misconfigured spec, not "
                        + "an anchor the patch left alone",
             elapsed_s: secs(t0) };

  // The patch did not touch the anchor file at all; the relation is about the
  // anchor, so there is nothing here for this gate to say.
  if (!cfg.post_images || !cfg.post_images[anchorFile])
    return { ...base, pass: true, skipped: "anchor file not in patch",
             elapsed_s: secs(t0) };

  const tids = spec.templateIds();
  const templates = tids.map((tid) => ({
    id: tid, args: spec.templateArgs(tid), baseline_fill: spec.baselineFor(tid),
  }));
  const skip = spec.structuralCodepoints();

  // ---- G3 (v32): candidates derived from the patch's own regex literals //
  // MEASURED (v31): the code-point sweep is exhaustive on ONE character and
  // so cannot reach a key that needs two at once.  N11_two_char is a regex
  // over two classes; N9_derived_prefix is a two-character prefix.  Both
  // walked through `fast`.  The regex is IN THE PATCH, so read it -- this is
  // a generator over what the patch introduced, not an enumeration of what
  // to look for, and by D18 generators stack onto the same relation freely.
  let regexCands = [], regexUnsupported = [], parseErr = null;
  try {
    const src = fs.readFileSync(cfg.post_images[anchorFile], "utf8");
    const g = candidatesFrom(parseSource(src));
    regexCands = g.candidates; regexUnsupported = g.unsupported;
  } catch (e) { parseErr = String(e.message).slice(0, 160); }
  const refCalls = spec.calls().map(([id, args]) => ({ id, args }));

  const preImg = (cfg.pre_images || {})[anchorFile];

  // ---- OUT OF SCOPE: pass, but recorded so no report implies it looked ---- //
  // WHERE THIS DIFFERS FROM mrgate.py (v30, deliberate): Python runs the
  // precondition BEFORE this check, because in-process it is free.  Here the
  // precondition costs a vitest start-up, so an out-of-scope anchor would pay
  // ~20s to produce something no verdict is read from.  The check moves first
  // and the report SAYS the precondition did not run -- silence about a
  // measurement that was skipped is the failure this project keeps making.
  // ★v66 (decision 1, step 3): this used to return `pass: true`.  MEASURED
  // (v65): copy the shipping spec, flip `decides` to false, point a cfg at the
  // copy, and N10_codepoint_class goes from killed_by_all ['check4','check8']
  // to ['check4'] -- check8 stops sweeping for 38.9s and returns a green in
  // 0.1s -- while freeze reports nothing, because the spec is neither in the
  // manifest nor in the repo.  One unfrozen boolean, one hard gate's kill gone,
  // no trace.
  //
  // The gate was never silent: `skipped` and `inapplicable_by_declaration` were
  // both there.  What was wrong is the VALUE of `pass` and the summary built
  // from it -- `check8=pass`, indistinguishable from a sweep that ran and found
  // nothing.  That is v29's thirteenth lesson (§0-c) in a second place.
  //
  // Note the gate disagreed with ITSELF: an empty `templates` list already
  // returned `pass: false, inapplicable: true` (measured in v65 as Z6).  Two
  // ways of being unable to do the job, opposite shapes, and the cheap one to
  // reach was the one that counted as green.
  //
  // ⛔ THE SWEEP'S PASS CONDITION IS UNTOUCHED.  `pass: true` still means, and
  // only means, "the sweep ran and found no divergence".
  if (!spec.decides)
    return { ...base, pass: false, inapplicable: true,
             skipped: OUT_OF_SCOPE,
             inapplicable_by_declaration: true, spec: spec.name,
             abstained_templates: {},
             precondition: { ran: false, why: "the anchor is declared not to "
                           + "decide, so the sweep is out of scope and the "
                           + "precondition was not measured either" },
             elapsed_s: secs(t0) };

  // ---- precondition + sweep, in ONE vitest run (v30) ---------------------- //
  // The probe imports the PRE image alongside the post one and runs the
  // precondition first, skipping the post sweep for any template that abstains
  // -- so folding the runs together does not cost more than it saves.
  const restore = installImages(repo, cfg.post_images);
  try {
    const r = sweepAxis(repo, anchorFile, anchorFunc, templates, {
      projection: spec.projection, refCalls, skipCodepoints: skip,
      maxCp, precondMaxCp, preImage: preImg, candidates: regexCands,
      cap: CAP, gatesDir,
    });
    if (!r.ok)
      return { ...base, pass: false, inapplicable: true,
               fail_reason: "the sweep could not run: " + r.why,
               driver_stderr: r.stderr_tail, elapsed_s: secs(t0) };

    const abstained = {};
    for (const s of r.pre_sweeps)
      if (s.n_divergent > 0)
        abstained[s.id] = {
          n_divergent_on_pre: s.n_divergent,
          reason: "the relation is already violated by the unpatched anchor, "
                + "so it is not a property of this anchor",
          sample_cp: s.divergent.slice(0, 5).map((d) => "0x" + d.cp.toString(16)),
        };
    base.abstained_templates = abstained;
    base.precondition = preImg
      ? { ran: true, max_cp: precondMaxCp, folded_into_sweep_run: true,
          n_templates_checked: r.pre_sweeps.length }
      : { ran: false, why: "no pre image for the anchor file; the relation was "
                         + "not checked against the unpatched anchor" };

    const live = tids.filter((t) => !(t in abstained));
    if (!live.length)
      return { ...base, pass: true,
               skipped: "every template abstained: the relation does not hold "
                      + "for this anchor (see abstained_templates)",
               inapplicable_by_measurement: true, spec: spec.name,
               elapsed_s: secs(t0) };

    // DIRECTION (v12, measured; same restriction 検査12 carries).  Only a move
    // onto the ACCEPTED side is a violation: prepending characters legitimately
    // turns an accepted input into a rejected one, so a symmetric relation
    // rejects every patch that narrows an over-permissive predicate.
    const accepted = new Set(r.refs.map((x) => JSON.stringify(x.verdict)));
    const classes = {};
    let violations = 0, other = 0, tried = 0, truncated = false;
    for (const s of r.sweeps) {
      const viol = s.divergent.filter((d) => accepted.has(JSON.stringify(d.verdict)));
      const rest = s.divergent.filter((d) => !accepted.has(JSON.stringify(d.verdict)));
      // n_divergent counts every move; the sample is capped at 8 by the probe,
      // so the split below is over the SAMPLE and is reported as such.
      violations += s.n_divergent > 0 && viol.length ? s.n_divergent : 0;
      other += s.n_divergent > 0 && !viol.length ? s.n_divergent : 0;
      tried += s.cp_tried;
      truncated = truncated || s.truncated;
      classes[s.id] = {
        baseline_verdict: s.baseline_verdict,
        n_divergent: s.n_divergent,
        cp_tried: s.cp_tried,
        truncated: s.truncated,
        direction: viol.length ? "toward_accepted" : (rest.length ? "other" : "none"),
        sample: s.divergent.slice(0, 8).map((d) => ({
          cp: "U+" + d.cp.toString(16).toUpperCase().padStart(4, "0"),
          verdict: d.verdict,
        })),
        secs: s.secs,
      };
    }

    // ---- G2/G3 の候補ヒット（多文字鍵）------------------------------------ //
    // 同じ関係・同じ向き制限。生成器が違うだけ（D18）。
    const candViol = (r.candidate_hits || [])
      .filter((h) => accepted.has(JSON.stringify(h.verdict)));
    const candOther = (r.candidate_hits || []).length - candViol.length;

    return {
      ...base,
      pass: violations === 0 && candViol.length === 0,
      n_divergent_total: violations,
      // --- multi-character generators (v32) --------------------------------- //
      n_candidate_violations: candViol.length,
      candidate_violations: candViol.slice(0, 8),
      n_candidate_other_direction: candOther,
      n_candidates_tried: r.n_candidates,
      regex_candidates: regexCands.slice(0, 16),
      n_regex_candidates: regexCands.length,
      regex_unsupported: regexUnsupported.slice(0, 8),
      n_harvested: r.n_harvested,
      harvested: r.harvested,
      generator_note: parseErr
        ? "THE POST IMAGE COULD NOT BE PARSED, so no regex candidate was "
          + "generated: " + parseErr
        : `${regexCands.length} from regex literals, ${r.n_harvested} harvested `
          + `by the spy, ${r.n_candidates} tried after de-duplication`
          + (regexUnsupported.length
             ? `; ${regexUnsupported.length} regex literal(s) NOT turned into a `
               + "candidate -- see regex_unsupported"
             : ""),
      n_other_direction: other,          // recorded, not judged
      classes,
      n_templates: tids.length,
      swept_templates: live,
      accepted_reference: r.refs,
      structural_excluded: spec.structural,
      cp_tried_total: tried,
      coverage_note: truncated
        ? `CAP-TRUNCATED at ${CAP} divergences in at least one class; the rest `
          + "of that class's axis was not swept."
        : `every code point below ${"0x" + maxCp.toString(16)} was tried in every `
          + "live class, minus the structural exclusions",
      projection: spec.projection,
      spec: spec.name,
      sweep_secs: r.secs,
      elapsed_s: secs(t0),
      elapsed_s_wall: +((wall() - w0) / 1000).toFixed(2),
      node_uptime_s: +process.uptime().toFixed(2),
    };
  } finally { restore(); }
}

// --------------------------------------------------------------------------- //
if (process.argv[2]) {
  const cfg = JSON.parse(fs.readFileSync(process.argv[2], "utf8"));
  const r = run(cfg);
  console.log(JSON.stringify(r, null, 1));
  process.exit(r.pass ? 0 : 1);
}
