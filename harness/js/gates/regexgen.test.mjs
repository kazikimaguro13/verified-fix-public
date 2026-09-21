// ★v134 (judgement 61): was an absolute path into the RUNNING copy of the
// gates.  This file sits next to regexgen.mjs in both places (the
// repository and $JS_GATES_DIR), so a relative specifier resolves to the
// same module wherever the test is run from, and names no machine.
import { sample } from "./regexgen.mjs";

const CASES = [
  // 実際の攻撃が使っているもの
  ["^[\\u2400-\\u243F]", "", "N10 の1文字クラス"],
  ["^[\\u2400-\\u243F][\\u2500-\\u257F]", "", "N11 の2文字クラス"],
  // 一般的な形
  ["^[A-Za-z][A-Za-z0-9_]{0,39}$", "", "識別子の形"],
  ["^ce", "", "素のリテラル接頭辞"],
  ["^(foo|bar)_\\d+$", "", "選択＋量化"],
  ["[^a-z]", "", "否定クラス"],
  ["^\\w+@\\w+\\.\\w+$", "", "メールらしき形"],
  ["a{3}b", "", "回数指定"],
  ["^(?:x)?y", "", "非捕獲グループ＋?"],
  // 届かないと宣言したもの
  ["\\p{L}", "u", "★プロパティ escape（未対応のはず）"],
  ["(a)\\1", "", "★後方参照（未対応のはず）"],
  ["(?=x)y", "", "★先読み（未対応のはず）"],
];

const esc = (s) => JSON.stringify(s).replace(/[-￿]/g,
  (c) => "\\u" + c.charCodeAt(0).toString(16).padStart(4, "0"));

for (const [p, f, label] of CASES) {
  const r = sample(p, f);
  console.log("%s  /%s/%s\n    -> %s",
    r.ok ? "OK  " : "NG  ", p, f,
    r.ok ? esc(r.value) + "   [" + label + "]" : r.why + "   [" + label + "]");
}
