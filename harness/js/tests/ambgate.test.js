// 検査9 (ambgate.mjs) の単体テスト — 掃引計画の部分だけ。
//
// 掃引の本体はリポジトリと vitest を要るので、実測（v22 の実クライアント（Next.js／TS の業務ポータル）走行）が統合テスト。
// ここで固定するのは、**このゲートが他と違う理由になっている2つの判断**:
//   1. Tier 1 をソース自身の比較構造から収穫する（辞書順だと予算が肝心の値に届かない）
//   2. 語彙を pre ∪ post の **和集合** にする（差分だと「既にそこに在るもの」に届かない）

import { describe, it, expect } from "vitest";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { plan } from "../gates/ambgate.mjs";

const TMP = fs.mkdtempSync(path.join(os.tmpdir(), "ambgate-"));
let n = 0;
function write(src) {
  const p = path.join(TMP, `f${n++}.ts`);
  fs.writeFileSync(p, src, "utf8");
  return p;
}
const mk = (pre, post) => plan({
  pre_images: { "a.ts": write(pre) },
  post_images: { "a.ts": write(post) },
});

describe("検査9: 掃引計画", () => {
  it("環境変数を1つも読まないファイルでも、軸は空にならない", () => {
    // 「読んでいる鍵が無い＝アンビエント依存が無い」ではない。パッチが新しく
    // 読み始める可能性があるので、合成の鍵を必ず1本持つ。
    const p = mk("export const a = 1;\n", "export const a = 2;\n");
    expect([...p.keys]).toContain("VF_UNSEEN_A");
  });

  it("読まれている env の鍵はすべて軸になる", () => {
    const p = mk("export const a = process.env.ALPHA;\n",
                 "export const a = process.env.ALPHA;\nexport const b = process.env.BETA;\n");
    expect([...p.keys].sort()).toEqual(["ALPHA", "BETA", "VF_UNSEEN_A"]);
  });

  // ---- 判断1: Tier 1 をソースから収穫する ------------------------------- //
  it("Tier 1: env と比較されている値をソースから収穫する", () => {
    const p = mk("export const a = process.env.NODE_ENV === 'production';\n",
                 "export const a = process.env.NODE_ENV === 'production';\n");
    expect(p.compared.NODE_ENV).toBeDefined();
    expect([...p.compared.NODE_ENV]).toContain("production");
    const first = p.settings.filter((s) => s.tier === 1);
    expect(first.map((s) => `${s.k}=${s.v}`)).toContain("NODE_ENV=production");
  });

  it("Tier 1 は掃引の先頭に来る（辞書順だと予算が届かない）", () => {
    const src = "export const a = process.env.NODE_ENV === 'zzz_late_value';\n"
              + "export const b = ['aaa', 'bbb', 'ccc'];\n";
    const p = mk(src, src);
    const i = p.settings.findIndex((s) => s.v === "zzz_late_value");
    const j = p.settings.findIndex((s) => s.v === "aaa");
    expect(i).toBeGreaterThanOrEqual(0);
    expect(i, "辞書順で先に来る 'aaa' より後ろに置かれている").toBeLessThan(j);
  });

  it("比較の左右どちらに env があっても収穫する", () => {
    const p = mk("export const a = 1;\n",
                 "export const a = 'prod_x' === process.env.MODE;\n");
    expect([...(p.compared.MODE || [])]).toContain("prod_x");
  });

  // ---- 判断2: 語彙は pre ∪ post ----------------------------------------- //
  it("語彙は差分ではなく和集合（M7 型に届くための条件）", () => {
    // 'production' は pre にも post にも在る。差分を取ると消える。
    const pre = "export const a = process.env.NODE_ENV === 'production';\n";
    const post = pre + "export function f() { return 1; }\n";
    const p = mk(pre, post);
    expect([...p.strings], "pre 側のリテラルが語彙から落ちている")
      .toContain("production");
  });

  // ---- 不在・空も値である ------------------------------------------------ //
  it("unset と空文字を早い段に入れる（真偽値テストが鍵にするのはそこ）", () => {
    const p = mk("export const a = process.env.FLAG;\n",
                 "export const a = !process.env.FLAG;\n");
    const early = p.settings.filter((s) => s.tier <= 1.5);
    expect(early.some((s) => s.k === "FLAG" && s.v === null),
      "unset が設定に入っていない").toBe(true);
    expect(early.some((s) => s.k === "FLAG" && s.v === ""),
      "空文字が設定に入っていない").toBe(true);
  });

  it("同じ設定を二度入れない", () => {
    const src = "export const a = process.env.X === 'v';\nexport const b = 'v';\n";
    const p = mk(src, src);
    const ids = p.settings.map((s) => s.label);
    expect(new Set(ids).size).toBe(ids.length);
  });

  // ---- 連言に届くための対 ------------------------------------------------ //
  // MEASURED (v22): M5_ambient keys on
  //   process.env.NODE_ENV !== 'test' && !process.env.VITEST
  // 1軸ずつ動かす掃引は、どちらの設定でも一方の項が偽のままなので何も見えない。
  // 検査12 の R4_two_char_key と同型で、答えも同じ — 収穫してから積を掃く。
  it("収穫した設定の対を掃く（連言で鍵にされたら1軸では届かない）", () => {
    const src = "export const a = process.env.NODE_ENV !== 'test' && !process.env.APP_TIER;\n";
    const p = mk(src, src);
    const pairs = p.settings.filter((s) => s.tier === 1.7);
    expect(pairs.length, "対が作られていない").toBeGreaterThan(0);
    const both = pairs.find((s) => "NODE_ENV" in s.set && "APP_TIER" in s.set);
    expect(both, "2つの鍵を同時に動かす設定が無い").toBeDefined();
  });

  // ---- 動かせない軸は「動かなかった軸」ではない ------------------------- //
  // MEASURED (v22): M5_ambient keys on `!process.env.VITEST`, and the sweep was
  // silent -- not because moving VITEST changed nothing, but because vitest
  // re-sets it inside its own worker and the sweep never moved it at all.
  // Checked directly: the same NODE_ENV=production that makes M7's oracle fail
  // leaves M5's passing with VITEST unset, empty, or paired.
  it("ランナーが所有する変数は掃引対象にせず、動かせない軸として報告する", () => {
    const src = "export const a = !process.env.VITEST && process.env.NODE_ENV === 'x';\n";
    const p = mk(src, src);
    expect(p.inert, "VITEST が inert として報告されていない").toContain("VITEST");
    expect(p.settings.some((s) => "VITEST" in s.set),
      "動かせない軸を掃引設定に入れている＝沈黙が証拠に化ける").toBe(false);
    // 他の鍵はふつうに掃く
    expect(p.settings.some((s) => "NODE_ENV" in s.set)).toBe(true);
  });

  it("対は同じ鍵どうしでは作らない（後勝ちになるだけで対ではない）", () => {
    const src = "export const a = process.env.K === 'x' || process.env.K === 'y';\n";
    const p = mk(src, src);
    for (const s of p.settings.filter((x) => x.tier === 1.7))
      expect(Object.keys(s.set).length).toBe(2);
  });

  it("対は単独の設定より後、tier 2 より前に置く", () => {
    const src = "export const a = process.env.A === 'x' && process.env.B === 'y';\n";
    const p = mk(src, src);
    const lastSingle = p.settings.map((s) => s.tier).lastIndexOf(1.5);
    const firstPair = p.settings.findIndex((s) => s.tier === 1.7);
    const firstT2 = p.settings.findIndex((s) => s.tier === 2);
    expect(firstPair).toBeGreaterThan(lastSingle);
    if (firstT2 >= 0) expect(firstPair).toBeLessThan(firstT2);
  });

  it("解析できないイメージは黙って空にせず報告する", () => {
    const p = mk("export const = = ;\n", "export const a = 1;\n");
    expect(p.errs.length).toBeGreaterThan(0);
  });
});
