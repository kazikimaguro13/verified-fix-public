// fccorpus.mjs — D5「ファズコーパスの資産化」の JS 実装。
//
// 実測で確定: fast-check 4.9.0 に Hypothesis の DirectoryBasedExampleDatabase
// 相当は **存在しない**。持っているのは
//   * 失敗時に印字される {seed, path, endOnFailure}（手で控えれば再現できる）
//   * `examples: [...]` （毎回最初に必ず走る固定例。回帰ピン留め用）
// のみ。よって永続化は自前で実装する。
//
// ここでの実装:
//   fc.assert (throw する) ではなく fc.check (RunDetails を返す) を使い、
//   `counterexample` を JSON コーパスに追記 → 次回以降 `examples` として先頭注入。
//   これで「一度見つけた反例は二度と失われない」= 単調増加する資産になる。

import fs from "node:fs";
import path from "node:path";
import fc from "fast-check";

export function loadCorpus(file) {
  try {
    return JSON.parse(fs.readFileSync(file, "utf8"));
  } catch {
    return [];
  }
}

function saveCorpus(file, corpus) {
  fs.mkdirSync(path.dirname(file), { recursive: true });
  fs.writeFileSync(file, JSON.stringify(corpus, null, 1));
}

// ---- 失敗の種別分類（検査3 が JS で成立するための鍵）----
// fc.assert は失敗理由を "Property failed after N tests" に潰してしまい、
// 「T が挙動で落ちた」のか「T が壊れて落ちた（TypeError/未定義シンボル）」のかを
// 区別できない。これは攻撃#5（修正が導入したシンボルへの偽依存）を素通りさせる。
// fc.check の RunDetails.errorInstance は生の例外を保持しているので、
// **ハーネス側が assert をラップすれば構造判定に戻せる**（実測で確認）。
const STRUCTURAL = ["TypeError", "ReferenceError", "SyntaxError"];

export function classifyFailure(errorInstance) {
  const name = errorInstance && errorInstance.constructor && errorInstance.constructor.name;
  const msg = String((errorInstance && errorInstance.message) || "");
  if (STRUCTURAL.includes(name)) return { kind: "structural", errorName: name, message: msg.slice(0, 160) };
  if (/does not provide an export|Cannot find module|Failed to resolve import/i.test(msg))
    return { kind: "structural", errorName: name, message: msg.slice(0, 160) };
  return { kind: "behavioural", errorName: name, message: msg.slice(0, 160) };
}

function recordClass(rec) {
  const f = process.env.VF_TCLASS;
  if (!f) return;
  let arr = [];
  try { arr = JSON.parse(fs.readFileSync(f, "utf8")); } catch { /* noop */ }
  arr.push(rec);
  fs.mkdirSync(path.dirname(f), { recursive: true });
  fs.writeFileSync(f, JSON.stringify(arr, null, 1));
}

/**
 * fc.assert の置き換え。反例を corpusFile に永続化し、次回以降必ず再生する。
 * 併せて失敗の種別（behavioural / structural）を VF_TCLASS に記録する。
 * @param {*} property  fc.property(...) の戻り
 * @param {{corpusFile:string, name?:string, numRuns?:number, seed?:number}} opts
 */
export function assertWithCorpus(property, opts) {
  const { corpusFile, name, ...params } = opts;
  const corpus = loadCorpus(corpusFile);

  const details = fc.check(property, {
    ...params,
    examples: [...corpus, ...(params.examples || [])],
  });

  if (details.failed) {
    const cls = classifyFailure(details.errorInstance);
    recordClass({ name: name || corpusFile, ...cls });
    const ce = details.counterexample;
    const key = JSON.stringify(ce);
    if (ce && !corpus.some((c) => JSON.stringify(c) === key)) {
      corpus.push(ce);
      saveCorpus(corpusFile, corpus);
    }
    const err = new Error(
      `[${cls.kind}] Property failed after ${details.numRuns} runs\n` +
      `  seed: ${details.seed}, path: "${details.counterexamplePath}"\n` +
      `  counterexample: ${key}\n` +
      `  underlying: ${cls.errorName}: ${cls.message}\n` +
      `  persisted to: ${corpusFile} (corpus size ${corpus.length})`,
    );
    err.failureKind = cls.kind;
    err.counterexample = ce;
    err.seed = details.seed;
    err.counterexamplePath = details.counterexamplePath;
    throw err;
  }
  return { numRuns: details.numRuns, corpusReplayed: corpus.length };
}
