// 検査7 (apigate.mjs) の回帰テスト。
//
// 最後の1件は **意図的に「捕まえられないこと」を固定している**。
// v22 で作った適応攻撃 M7_ambient_zero_new が示した境界で、
// 「ここまでは静的に見えない」を性質として書いておかないと、
// 次に誰かが「検査7 があるからアンビエントは大丈夫」と読んでしまう。

import { describe, it, expect } from "vitest";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { run } from "../gates/apigate.mjs";

const TMP = fs.mkdtempSync(path.join(os.tmpdir(), "apigate-"));
let n = 0;
function write(name, src) {
  const p = path.join(TMP, `${n++}_${name}`);
  fs.writeFileSync(p, src, "utf8");
  return p;
}
function gate(pre, post, groups = ["classify", "ambient"]) {
  return run(
    { pre_images: { "a.ts": write("pre.ts", pre) },
      post_images: { "a.ts": write("post.ts", post) } },
    new Set(groups)
  );
}

const PLAIN = "export function f(x: string) { return x.trim(); }\n";

describe("検査7: 未説明の分類・環境 API", () => {
  it("新しい名前が無ければ通す", () => {
    const r = gate(PLAIN, PLAIN + "export const g = 1;\n");
    expect(r.verdict).toBe("PASS");
  });

  it("curated list に無い新しい名前では発火しない（『新しい名前ならなんでも』ではない）", () => {
    const r = gate(PLAIN,
      PLAIN + "export function h(a: string[]) { return a.filter(Boolean).join('/'); }\n");
    expect(r.n_new_names).toBeGreaterThan(0);
    expect(r.verdict, "普通の新規名で発火している＝ゲートとして無価値").toBe("PASS");
  });

  // ---- G1: curated name ------------------------------------------------- //
  it("G1: アンビエント API の新規参照を出す", () => {
    const r = gate(PLAIN, PLAIN + "export const j = () => Math.random() > 0.5;\n");
    expect(r.verdict).toBe("ESCALATE");
    expect(r.by_generator.G1_curated_name).toBeGreaterThan(0);
    expect(r.flagged.map((x) => x.name)).toContain("random");
  });

  it("G1: 文字分類 API の新規参照を出す", () => {
    const r = gate(PLAIN, PLAIN + "export const k = (s: string) => s.normalize('NFD');\n");
    expect(r.verdict).toBe("ESCALATE");
    expect(r.flagged.map((x) => x.name)).toContain("normalize");
  });

  // ---- G2: ambient namespace key ---------------------------------------- //
  // MEASURED (v22): M5_ambient reads process.env.VITEST.  `process`, `env` and
  // `NODE_ENV` are all already in the pre image, so G1 is silent -- the only
  // new name is VITEST, an ENV VAR NAME, and listing env var names in a curated
  // list is the bad kind of enumeration.  G2 watches the SHAPE instead.
  it("G2: process.env から新しく読まれた鍵を、名前を列挙せずに出す", () => {
    const pre = "export const a = process.env.NODE_ENV === 'production';\n";
    const post = pre + "export const b = !process.env.VITEST;\n";
    const r = gate(pre, post);
    expect(r.verdict).toBe("ESCALATE");
    expect(r.by_generator.G2_ambient_key).toBe(1);
    expect(r.flagged.map((x) => x.name)).toContain("process.env.VITEST");
  });

  it("G2: 修正前から読まれている鍵は新規ではない", () => {
    const pre = "export const a = process.env.NODE_ENV === 'production';\n";
    const post = pre + "export const b = process.env.NODE_ENV !== 'production';\n";
    expect(gate(pre, post).verdict).toBe("PASS");
  });

  it("G2: 計算アクセスで鍵が静的に決まらないときは名指ししない", () => {
    // pre で既に process.env に触れているので「名前空間に新しく触った」分は出ない。
    // 残るのは「新しく読まれた鍵」だけで、`process.env[k]` の k は静的に決まらない。
    const pre = "export const a = process.env.NODE_ENV === 'production';\n" + PLAIN;
    const post = pre + "export const b = (k: string) => process.env[k];\n";
    const r = gate(pre, post);
    expect(r.by_generator.G2_ambient_key ?? 0,
      "静的に決まらない鍵を名指ししている").toBe(0);
  });

  it("G2: 名前空間そのものに初めて触ったときは出す", () => {
    // `process` を一度も触っていなかったファイルが触り始めるのは、それ自体が
    // 「アンビエントを引き始めた」という事実。深さに関わらず出す。
    const r = gate(PLAIN, PLAIN + "export const b = process.env.ANY;\n");
    expect(r.verdict).toBe("ESCALATE");
    expect(r.by_generator.G2_ambient_key).toBeGreaterThan(0);
  });

  // ---- G3: unicode property regex --------------------------------------- //
  // litgate は正規表現リテラルを対象外にしているので、これが無いと
  // `/\p{Mn}/u.test(c)` は検査6 からも G1 からも見えない。
  it("G3: 新規の Unicode プロパティ正規表現を出す", () => {
    const r = gate(PLAIN, PLAIN + "export const m = (c: string) => /\\p{Mn}/u.test(c);\n");
    expect(r.verdict).toBe("ESCALATE");
    expect(r.by_generator.G3_unicode_property_regex).toBe(1);
  });

  it("G3: 普通の正規表現では発火しない", () => {
    const r = gate(PLAIN, PLAIN + "export const m = (c: string) => /^[a-z]+$/.test(c);\n");
    expect(r.verdict).toBe("PASS");
  });

  // ---- 計器 -------------------------------------------------------------- //
  it("解析できないイメージは黙って空集合にせず、報告する", () => {
    const r = gate(PLAIN, "export const = = = ;\n");
    expect(r.parse_errors.length).toBeGreaterThan(0);
  });

  // ---- ★境界（意図的に捕まえられない）------------------------------------ //
  // v22 の適応攻撃 M7_ambient_zero_new。**新規の名前ゼロ・新規のリテラルゼロ・
  // 新規のアンビエント鍵ゼロ** で環境依存の分岐を作れる。修正前のファイルが
  // 既にその環境変数を読んでいる場合に限られるが、実案件では珍しくない。
  // **検査6 も検査7 も原理的に見えない。踏めるのは検査4（変異）だけ。**
  it("★境界: 既存の環境読み取りを再利用した分岐は、静的には見えない", () => {
    const pre = "export const a = process.env.NODE_ENV === 'production';\n"
              + "export function f(x: string) { return x.trim(); }\n";
    const post = "export const a = process.env.NODE_ENV === 'production';\n"
               + "export function f(x: string) {\n"
               + "  if (process.env.NODE_ENV === 'production') return x;\n"
               + "  return x.trim();\n"
               + "}\n";
    const r = gate(pre, post);
    expect(r.n_new_names, "新規の名前がゼロであること").toBe(0);
    expect(r.n_new_ambient_paths, "新規のアンビエント鍵がゼロであること").toBe(0);
    expect(r.verdict,
      "ここが PASS でなくなったら、この境界の記述（v22 §4）を書き直すこと").toBe("PASS");
  });
});
