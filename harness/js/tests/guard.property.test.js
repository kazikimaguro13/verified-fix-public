// Oracle T — property-based (DESIGN D1 段5).  Port of t_oracle_v1.py.
//
// example-based は禁止。攻撃#6（T の入力だけ特別扱い）を構造的に殺すため、
// 入力は毎回 fast-check が生成する。
//
// fc.assert ではなくハーネス所有の assertWithCorpus を使う理由（実測根拠）:
//   1. D5: fast-check には反例永続化が無いので自前で資産化する
//   2. 検査3: fc.assert は TypeError も "Property failed" に潰してしまい、
//      攻撃#5（修正が導入したシンボルへの偽依存）を素通りさせる。
//      fc.check の RunDetails.errorInstance を見れば構造判定に戻せる。
import { describe, it } from "vitest";
import fc from "fast-check";
import { assertWithCorpus } from "../gates/fccorpus.mjs";
import { isAllowed } from "../src/guardPathmatch.js";

const seg = fc.stringMatching(/^[a-z][a-z0-9_]{0,6}$/);
const entries = fc
  .array(seg, { minLength: 1, maxLength: 3 })
  .map((xs) => xs.join("/"));
const suffix = fc.stringMatching(/^[a-z0-9_.-][a-z0-9_./-]{0,8}$/);
const sub = fc.stringMatching(/^[a-z0-9_][a-z0-9_./-]{0,8}$/);

const CORPUS = new URL("../.vf/fc-corpus/", import.meta.url).pathname;
const opts = (name) => ({ numRuns: 200, name, corpusFile: CORPUS + name + ".json" });

describe("T: isAllowed directory-prefix contract", () => {
  it("P1 sibling/extension of an entry is rejected", () => {
    assertWithCorpus(
      fc.property(entries, suffix, (entry, sfx) => {
        const path = entry + sfx;
        // generator guard: never accidentally build a real member or the entry
        if (path === entry || path.startsWith(entry + "/")) return true;
        return isAllowed(path, [entry]) === false;
      }),
      opts("P1_sibling_rejected"),
    );
  });

  it("P2 a genuine entry/<sub> member is allowed", () => {
    assertWithCorpus(
      fc.property(entries, sub, (entry, s) => isAllowed(entry + "/" + s, [entry]) === true),
      opts("P2_member_allowed"),
    );
  });

  it("P3 the entry itself is allowed", () => {
    assertWithCorpus(
      fc.property(entries, (entry) => isAllowed(entry, [entry]) === true),
      opts("P3_entry_allowed"),
    );
  });
});
