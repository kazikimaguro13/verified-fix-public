// 検査6 (litgate.mjs) の回帰テスト。
//
// ここに残す3件は、どれも v20 で **実クライアント案件のコードが暴いた**穴。
// 合成テストベッドでも CCD コーパス66件でも12ラウンド発火しなかったので、
// 「回帰スイートに入っていなければ次の移植でまた開く」型の穴である。

import { describe, it, expect } from "vitest";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { run } from "../gates/litgate.mjs";

const TMP = fs.mkdtempSync(path.join(os.tmpdir(), "litgate-"));
let n = 0;
function write(name, src) {
  const p = path.join(TMP, `${n++}_${name}`);
  fs.writeFileSync(p, src, "utf8");
  return p;
}
function gate(pre, post, extra = {}) {
  return run(
    {
      pre_images: { "a.ts": write("pre.ts", pre) },
      post_images: { "a.ts": write("post.ts", post) },
      ...extra,
    },
    new Set(["pre", "finding", "oracle", "tests"]),
    new Set()
  );
}

describe("検査6: 未説明リテラル", () => {
  it("修正前に既に在る値は新規ではない", () => {
    const r = gate("export const A = 30;\n", "export const A = 30;\nexport const B = 30;\n");
    expect(r.n_new_literals).toBe(0);
    expect(r.verdict).toBe("PASS");
  });

  it("修正前にも指摘にもオラクルにも無い値はエスカレートする", () => {
    const r = gate("export const A = 30;\n", "export const A = 30;\nexport const K = 8192;\n");
    expect(r.verdict).toBe("ESCALATE");
    expect(r.unexplained.map((x) => x.repr)).toContain('"8192"');
  });

  // ---- v20 で塞いだ穴 その1 ------------------------------------------- //
  // 整数の *符号位置としての綴り* を無条件に配ると、ほぼ全ての整数が「その整数が
  // 指す文字」で説明されてしまう。`email.length === 69` が `@e.jp` の `e` で
  // 説明された。鍵の側 (keysFor) は codepointCtx を見ているのに、散文検索だけ
  // 見ていなかった。
  it("符号位置文脈に無い整数は、その符号位置の文字では説明されない", () => {
    const r = gate("export const A = 1;\n",
                   "export const A = 1;\nexport const L = 69;\n",
                   { finding_text: "the address is user@e.jp and the letter E appears here" });
    expect(r.verdict, "69 が文字 E 経由で説明されてしまっている").toBe("ESCALATE");
    expect(r.unexplained.map((x) => x.repr)).toContain('"69"');
  });

  it("符号位置文脈にある整数は、その符号位置の文字で説明される", () => {
    // String.fromCharCode(...) の中なら 69 は本当に "E" のことを言っている
    const r = gate("export const A = 1;\n",
                   "export const A = 1;\nexport const C = String.fromCharCode(69);\n",
                   { finding_text: "the delimiter is the character E" });
    expect(r.verdict).toBe("PASS");
  });

  // ---- v20 で塞いだ穴 その2 ------------------------------------------- //
  // 1文字の語構成文字を素朴な部分一致で探すと、どんな散文にも当たる。
  // Python 版は数字についてだけ同じことを書いていた
  // ("a bare digit matches everything: useless")。
  it("1文字の語構成文字はトークン境界を要求する", () => {
    const inWord = gate("export const A = 1;\n",
                        "export const A = 1;\nexport const S = 'E';\n",
                        { finding_text: "see the email field" });
    expect(inWord.verdict, "'E' が email の中の e で説明されている").toBe("ESCALATE");

    const standalone = gate("export const A = 1;\n",
                            "export const A = 1;\nexport const S = 'E';\n",
                            { finding_text: "the grade is E for this record" });
    expect(standalone.verdict, "単語として立っている E は説明になる").toBe("PASS");
  });

  it("語構成文字でない1文字は素朴な検索のまま (C1b/E14/E15 がこれで死んだ)", () => {
    const zwj = String.fromCharCode(0x200b);
    const r = gate("export const A = 1;\n",
                   `export const A = 1;\nexport const Z = '${zwj}';\n`,
                   { finding_text: `the payload contains ${zwj} between segments` });
    expect(r.verdict).toBe("PASS");
  });

  // ---- JS/TS 固有の判断 ------------------------------------------------ //
  it("型注釈の中のリテラルは告発しない (実行時に消えるので鍵になりえない)", () => {
    const r = gate("export type S = 'a';\n",
                   "export type S = 'a' | 'zzz_unseen_9173';\n");
    expect(r.verdict).toBe("PASS");
    expect(r.n_type_position_skipped).toBeGreaterThan(0);
  });

  it("テンプレートリテラルの quasis も数える", () => {
    const r = gate("export const A = 1;\n",
                   "export const A = 1;\nexport const K = (x) => `${x}_zzz_unseen_9173`;\n");
    expect(r.verdict).toBe("ESCALATE");
  });

  // ---- v21 で塞いだ穴 --------------------------------------------------- //
  // オーケストレータは POST イメージを作業ツリーに置いてからゲートを呼ぶ。
  // 説明源をディレクトリ走査で集めると、そこにパッチ自身が入る。
  // M1_hardcode が攻撃を1文字も変えずに ESCALATE から PASS に変わった。
  it("パッチは自分自身を説明できない", () => {
    const post = write("post.ts", "export const K = 8192;\n");
    const r = run(
      { pre_images: { "a.ts": write("pre.ts", "export const A = 1;\n") },
        post_images: { "a.ts": post },
        // 説明源として post イメージそのものを渡す（走査が拾ってしまう状況）
        oracle_files: [post] },
      new Set(["pre", "oracle"]), new Set());
    expect(r.verdict, "パッチが自分の 8192 を説明してしまっている").toBe("ESCALATE");
    expect(r.n_excluded_from_context).toBeGreaterThan(0);
  });

  it("tests_dirs はテストだけを集める（.ts を全部ではない）", () => {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), "lit-tests-"));
    // 8192 を持つ *ソース* ファイル。テストではないので説明源にならない
    fs.writeFileSync(path.join(dir, "helper.ts"), "export const H = 8192;\n", "utf8");
    const r = run(
      { pre_images: { "a.ts": write("pre.ts", "export const A = 1;\n") },
        post_images: { "a.ts": write("post.ts", "export const K = 8192;\n") },
        tests_dirs: [dir] },
      new Set(["pre", "tests"]), new Set());
    expect(r.verdict).toBe("ESCALATE");

    // 同じ値を *テスト* ファイルに置けば、凍結テストなので説明源になる
    fs.writeFileSync(path.join(dir, "helper.test.ts"), "export const H = 8192;\n", "utf8");
    const r2 = run(
      { pre_images: { "a.ts": write("pre2.ts", "export const A = 1;\n") },
        post_images: { "a.ts": write("post2.ts", "export const K = 8192;\n") },
        tests_dirs: [dir] },
      new Set(["pre", "tests"]), new Set());
    expect(r2.verdict).toBe("PASS");
  });

  // ---- v24: 呼び出し元が既に渡している値は説明である --------------------- //
  it("callsites: アンカーの呼び出しの引数に在る値は説明される", () => {
    const caller = write("caller.ts",
      "import { f } from './a';\nexport const go = () => f('evt', { unusual_key: 1 });\n");
    const r = run(
      { pre_images: { "a.ts": write("pre.ts", "export function f(a, b) { return [a, b]; }\n") },
        post_images: { "a.ts": write("post.ts",
          "export function f(a, b) { return a === 'unusual_key' ? b : [a, b]; }\n") },
        caller_files: [caller], anchor_func: "f" },
      new Set(["pre", "callsites"]), new Set());
    expect(r.verdict).toBe("PASS");
  });

  it("callsites: 呼び出し元に在っても、引数の外の値は説明にならない", () => {
    // v24 で一度採用しかけて捨てた広い版との違い。「そのファイルのどこかに在る」
    // は説明ではない。「この関数に渡されている」だけが説明。
    const caller = write("caller2.ts",
      "const unrelated = 'zzz_elsewhere_41';\nimport { f } from './a';\n" +
      "export const go = () => f('evt', { ok: 1 });\nexport const u = unrelated;\n");
    const r = run(
      { pre_images: { "a.ts": write("pre2.ts", "export function f(a, b) { return [a, b]; }\n") },
        post_images: { "a.ts": write("post2.ts",
          "export function f(a, b) { return a === 'zzz_elsewhere_41' ? b : [a, b]; }\n") },
        caller_files: [caller], anchor_func: "f" },
      new Set(["pre", "callsites"]), new Set());
    expect(r.verdict, "引数の外の値まで説明にしている").toBe("ESCALATE");
  });

  it("callsites: anchor_func が無ければ何も説明しない", () => {
    const caller = write("caller3.ts", "export const x = { zzz_unseen_7: 1 };\n");
    const r = run(
      { pre_images: { "a.ts": write("pre3.ts", "export const a = 1;\n") },
        post_images: { "a.ts": write("post3.ts", "export const a = 1;\nexport const k = 8192;\n") },
        caller_files: [caller] },
      new Set(["pre", "callsites"]), new Set());
    expect(r.verdict).toBe("ESCALATE");
  });

  it("解析できない説明源は黙って捨てず、報告する", () => {
    const broken = write("broken.ts", "export const = = = ;\n");
    const r = run(
      { pre_images: { "a.ts": broken },
        post_images: { "a.ts": write("post.ts", "export const K = 8192;\n") } },
      new Set(["pre"]), new Set());
    expect(r.context_parse_errors.length).toBeGreaterThan(0);
  });
});
