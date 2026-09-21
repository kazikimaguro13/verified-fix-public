// typegate.mjs — 検査13: the patch must not introduce a type error.
//
// WHY (v100, decision 20, owner 2026-09-09): the pipeline never looked at the
// build or the type checker.  R4/R5 run the suite, but vitest does not
// typecheck, so a patch whose only defect is a type error passed every gate:
// MEASURED, `Z100_type_error` (S1_control with `let droppedKeys: string = 0;`)
// came back `accepted: true` in BOTH profiles while `tsc --noEmit` reported
// three new errors.  ECC's verification-loop puts build and typecheck first for
// exactly this reason; this gate is that step, made differential.
//
// DIFFERENTIAL, not absolute.  The repository already has type errors of its
// own (MEASURED: 3, in an oracle of ours).  A gate that judged the absolute
// count would reject every patch in such a repo and would be judging the repo,
// not the patch.  So the gate runs tsc twice -- once with the PRE images, once
// with the POST images -- and fails only on errors that are new in POST.
// Errors are compared by (file, TS code, message), never by line number, since
// a patch shifts lines without introducing anything.
//
// usage: typegate.mjs <cfg.json>
//   cfg: { repo, pre_images, post_images, tsconfig?, typecheck_cmd? }
import fs from "node:fs";
import path from "node:path";
import { spawnSync } from "node:child_process";

const now = () => performance.now();

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

/** One tsc run -> { ok, errors: [{file, code, message, raw}], raw_tail } */
function typecheck(repo, cfg) {
  // ★v128 (decision 49, owner 2026-09-19): `--pretty false`, on the DEFAULT
  // command only.
  // WHAT HAPPENED (v126, zod454): zod's tsconfig inherits `"pretty": true`, so
  // tsc printed `<file>:<L>:<C> - error TSxxxx: msg` with ANSI colour.  Neither
  // the `(L,C):` pattern below nor the `^error TS` fallback matched one line,
  // so the gate reported `n_pre_existing 0 / n_post_total 0` beside `pre_exit 2
  // / post_exit 2` and returned `pass: true`.  Exit 2 means "diagnostics were
  // reported" (TS 5.5.4, tsc.js:125508-125525).
  // WHY THE FLAG BEATS THE tsconfig -- read off tsc 5.5.4, not off a run:
  //   the config parser merges as `extend(existingOptions, parsedConfig.options)`
  //   (tsc.js:37765) with existingOptions = the command line, and `extend`
  //   (tsc.js:771-784) copies `second` first and then lets `first` overwrite it;
  //   `pretty` is a plain boolean CLI option (tsc.js:35589-35596), so
  //   `--pretty false` parses to boolean false (tsc.js:37051-37056); the
  //   reporter is then chosen from that merged object by shouldBePretty /
  //   updateReportDiagnostic (tsc.js:128307-128322).
  // ⛔ NOT MEASURED: that any repository's output is byte-identical with the
  //   flag.  Nothing in this comment comes from a run.
  // ⛔ NOT added to `cfg.typecheck_cmd`: that string is the caller's command and
  //   this gate does not rewrite it.
  const args = cfg.typecheck_cmd
    ? cfg.typecheck_cmd.split(" ")
    : ["--no-install", "tsc", "--noEmit", "-p", cfg.tsconfig || "tsconfig.json",
       "--pretty", "false"];
  const r = spawnSync("npx", args, {
    cwd: repo, encoding: "utf8", maxBuffer: 64 * 1024 * 1024, shell: false,
  });
  const out = String(r.stdout || "") + String(r.stderr || "");
  const errors = [];
  for (const line of out.split("\n")) {
    // src/lib/x.ts(394,7): error TS2322: Type 'number' is not assignable ...
    const m = line.match(/^(.*?)\((\d+),(\d+)\):\s+error\s+(TS\d+):\s+(.*)$/);
    if (m) errors.push({ file: m[1], code: m[4], message: m[5].trim(), raw: line.trim() });
    else if (/^error\s+TS\d+/.test(line)) errors.push({ file: "", code: (line.match(/TS\d+/) || [""])[0], message: line.trim(), raw: line.trim() });
  }
  return { spawn_ok: r.error === undefined, exit: r.status, errors, raw_tail: out.split("\n").slice(-6).join("\n") };
}

const key = (e) => `${e.file}|${e.code}|${e.message}`;

export function run(cfg) {
  const t0 = now();
  const base = { gate: "check13_typecheck" };
  const repo = cfg.repo;

  // POST first: it is the state the rest of the pipeline runs in.
  const restorePost = installImages(repo, cfg.post_images);
  let post;
  try { post = typecheck(repo, cfg); } finally { restorePost(); }

  if (!post.spawn_ok || post.exit === null)
    return { ...base, pass: false, gate_could_not_run: true,
             fail_reason: "the type checker could not be started -- this is not a verdict about the patch",
             post_exit: post.exit, raw_tail: post.raw_tail,
             elapsed_s: +((now() - t0) / 1000).toFixed(2) };

  const restorePre = installImages(repo, cfg.pre_images);
  let pre;
  try { pre = typecheck(repo, cfg); } finally { restorePre(); }

  // ★v128 (decision 50, owner 2026-09-20): the PRE side had no such door.
  // MEASURED (read, typegate.mjs:73-80): a pre-side spawn failure left
  // pre.errors empty, so every post error counted as introduced and the
  // patch was REJECTED for a checker that never ran.  Same box as post.
  if (!pre.spawn_ok || pre.exit === null)
    return { ...base, pass: false, gate_could_not_run: true,
             fail_reason: "the type checker could not be started on the PRE image -- this is not a verdict about the patch",
             pre_exit: pre.exit, post_exit: post.exit, raw_tail: pre.raw_tail,
             elapsed_s: +((now() - t0) / 1000).toFixed(2) };

  // ★v128 (decision 49, owner 2026-09-19): D22 -- "I understood none of tsc's
  // output" must not be reported as "tsc found nothing".
  // On zod454 both runs exited 2 -- diagnostics were reported
  // (tsc.js:125508-125525) -- while the loop in typecheck() parsed 0 lines from
  // either, because the tsconfig's `"pretty": true` gives a format neither
  // pattern matches.  The differential below then compared an empty set with an
  // empty set: an unconditional `pass: true` for every patch in that repository.
  // ⛔ NARROW ON PURPOSE.  exit 0 with 0 parsed is the ordinary clean-repo case
  //   and is untouched.  exit != 0 with >= 1 parsed goes to the differential
  //   exactly as before.  Only "exited non-zero AND parsed nothing" is caught.
  // ⛔ COULD NOT RUN, not a kill -- the same shape the spawn failure above
  //   returns.  run_gates.mjs reads `gate_could_not_run` (run_gates.mjs:955-958)
  //   and files the gate in errored_gates, which blocks acceptance without
  //   naming the patch the culprit.
  // The counts are named *_parsed, not *_existing / *_total: what is known here
  // is how many lines the parser READ, not how many errors the repository has.
  // POST is tested first because it is the side the rest of the pipeline runs
  // in, so its raw_tail is the more useful one to carry out.
  const mute = [["post", post], ["pre", pre]].find(
    ([, r]) => r.spawn_ok && r.exit !== 0 && r.errors.length === 0);
  if (mute)
    return { ...base, pass: false, gate_could_not_run: true,
             fail_reason: `tsc exited ${mute[1].exit} on ${mute[0]} but no ` +
                          `diagnostic line could be parsed ` +
                          `(output format not understood?)`,
             pre_exit: pre.exit, post_exit: post.exit,
             n_pre_parsed: pre.errors.length, n_post_parsed: post.errors.length,
             raw_tail: mute[1].raw_tail,
             elapsed_s: +((now() - t0) / 1000).toFixed(2) };

  const preKeys = new Set(pre.errors.map(key));
  const introduced = post.errors.filter((e) => !preKeys.has(key(e)));
  const postKeys = new Set(post.errors.map(key));
  const fixed = pre.errors.filter((e) => !postKeys.has(key(e)));

  return {
    ...base,
    pass: introduced.length === 0,
    n_introduced: introduced.length,
    introduced: introduced.slice(0, 12).map((e) => e.raw),
    // stated, not implied: the repo's own errors are not this patch's fault,
    // and a patch that FIXES one is worth seeing too.
    n_pre_existing: pre.errors.length,
    n_post_total: post.errors.length,
    n_fixed_by_patch: fixed.length,
    fixed_by_patch: fixed.slice(0, 6).map((e) => e.raw),
    pre_exit: pre.exit, post_exit: post.exit,
    fail_reason: introduced.length
      ? `the patch introduces ${introduced.length} type error(s) the pre image did not have`
      : null,
    elapsed_s: +((now() - t0) / 1000).toFixed(2),
  };
}

// --------------------------------------------------------------------------- //
if (process.argv[2]) {
  const cfg = JSON.parse(fs.readFileSync(process.argv[2], "utf8"));
  const r = run(cfg);
  console.log(JSON.stringify(r, null, 1));
  process.exit(r.pass ? 0 : 1);
}
