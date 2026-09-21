// corpusdemo.mjs — D5 反例永続化の実証。
//   1回目: 欠陥コードで反例を発見 -> corpus に追記
//   2回目: 同じ反例が examples として先頭再生され、numRuns=0 相当で即死
//   3回目: 修正コードでは corpus 全件が通り、資産として残り続ける
import fs from "node:fs";
import fc from "fast-check";
import { assertWithCorpus, loadCorpus } from "../gates/fccorpus.mjs";
import { isAllowed as buggy } from "../images/pre/guardPathmatch.js";
import { isAllowed as fixed } from "../images/post/guardPathmatch.js";

const CORPUS = new URL("../.vf/fc-corpus-isAllowed.json", import.meta.url).pathname;
fs.rmSync(CORPUS, { force: true });

const seg = fc.stringMatching(/^[a-z][a-z0-9_]{0,6}$/);
const entries = fc.array(seg, { minLength: 1, maxLength: 3 }).map((x) => x.join("/"));
const suffix = fc.stringMatching(/^[a-z0-9_.-][a-z0-9_./-]{0,8}$/);

const mkProp = (impl) => fc.property(entries, suffix, (entry, sfx) => {
  const p = entry + sfx;
  if (p === entry || p.startsWith(entry + "/")) return true;
  return impl(p, [entry]) === false;
});

const out = [];
const attempt = (label, impl) => {
  const t0 = performance.now();
  try {
    const r = assertWithCorpus(mkProp(impl), { corpusFile: CORPUS, numRuns: 200 });
    out.push({ label, result: "PASS", ...r, ms: +(performance.now() - t0).toFixed(1) });
  } catch (e) {
    out.push({ label, result: "FAIL", counterexample: e.counterexample,
      seed: e.seed, ms: +(performance.now() - t0).toFixed(1),
      corpus_size: loadCorpus(CORPUS).length });
  }
};

attempt("run1 buggy (discovery)", buggy);
attempt("run2 buggy (replay from corpus)", buggy);
attempt("run3 buggy (replay again)", buggy);
attempt("run4 fixed (corpus must all pass)", fixed);

console.log(JSON.stringify({
  corpus_file: CORPUS,
  corpus_final: loadCorpus(CORPUS),
  runs: out,
}, null, 1));
