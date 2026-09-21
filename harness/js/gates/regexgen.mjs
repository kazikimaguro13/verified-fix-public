// regexgen.mjs — 正規表現リテラルから「それに合う文字列」を1本作る。
//
// WHY (v31 measured)
// ------------------
// `fast` accepts N11_two_char: the key is decided by a regex over TWO character
// classes, so 検査8's single-character relation cannot reach it and 検査12's spy
// never sees it (RegExp.prototype.test is not String.prototype).  Only 検査4
// reaches it, and 検査4 is strict-only.
//
// The regex is right there in the patch.  This is not an enumeration of what to
// look for -- it is a GENERATOR that reads the code the patch itself introduced,
// the same shape as 検査12's "string literals in the post image".  Per D18 the
// relation is what produces false positives and the generators only produce
// coverage, so generators stack freely.
//
// IT CHECKS ITS OWN WORK
// ----------------------
// Every candidate is tested against the real RegExp before being returned.  A
// generator that emits a string which does not match would hand the gate a
// candidate that proves nothing, and the gate would report "no divergence" --
// an unmeasured thing dressed as a clean result, which is the failure this
// project keeps making (§0-c).  What cannot be generated is REPORTED as
// unsupported, not silently dropped.
//
// WHAT IT DOES NOT REACH (stated up front)
//   * a regex built at run time -- `new RegExp(a + b)`.  This reads LITERALS.
//   * back-references, lookaround, and \p{...} property escapes: reported
//     unsupported rather than guessed at.

const CLASS_PICK = {
  d: "0", w: "a", s: " ", D: "a", W: " ", S: "a",
};

/** One string matching `pattern`, or null with a reason. */
export function sample(pattern, flags) {
  let i = 0;
  const src = pattern;
  const unsupported = (why) => { throw new Error(why); };

  // A character class returns ONE representative character.
  function readClass() {
    // src[i] === "["
    i++;
    let neg = false;
    if (src[i] === "^") { neg = true; i++; }
    const members = [];       // single chars
    const ranges = [];        // [lo, hi] as code points
    let first = true;
    while (i < src.length && (src[i] !== "]" || first)) {
      first = false;
      const lo = readOne();
      if (src[i] === "-" && src[i + 1] !== "]" && i + 1 < src.length) {
        i++;
        const hi = readOne();
        ranges.push([lo.codePointAt(0), hi.codePointAt(0)]);
      } else members.push(lo);
    }
    if (src[i] !== "]") unsupported("unterminated character class");
    i++;
    if (!neg) {
      if (ranges.length) return String.fromCodePoint(ranges[0][0]);
      if (members.length) return members[0];
      unsupported("empty character class");
    }
    // Negated: find something the class does NOT contain.  MEASURED (v32): a
    // first version tried only a-z, so `[^a-z]` -- the commonest negated class
    // there is -- reported "excludes every candidate tried".  The pool has to
    // span more than the range most people negate.
    const pool = [];
    for (let cp = 0x61; cp <= 0x7a; cp++) pool.push(cp);   // a-z
    for (let cp = 0x41; cp <= 0x5a; cp++) pool.push(cp);   // A-Z
    for (let cp = 0x30; cp <= 0x39; cp++) pool.push(cp);   // 0-9
    for (const cp of [0x5f, 0x2d, 0x2e, 0x20, 0x21, 0x40, 0x7e]) pool.push(cp);
    for (const cp of [0xe9, 0x3b1, 0x4e00, 0x2400]) pool.push(cp);
    for (const cp of pool) {
      const ch = String.fromCodePoint(cp);
      if (members.includes(ch)) continue;
      if (ranges.some(([a, b]) => cp >= a && cp <= b)) continue;
      return ch;
    }
    unsupported("negated class excludes every candidate tried");
  }

  /** One literal character (handling escapes) at the cursor. */
  function readOne() {
    const c = src[i];
    if (c !== "\\") { i++; return c; }
    i++;
    const e = src[i++];
    if (e === "u") {
      if (src[i] === "{") {
        const j = src.indexOf("}", i);
        const cp = parseInt(src.slice(i + 1, j), 16);
        i = j + 1;
        return String.fromCodePoint(cp);
      }
      const cp = parseInt(src.slice(i, i + 4), 16);
      i += 4;
      return String.fromCodePoint(cp);
    }
    if (e === "x") { const cp = parseInt(src.slice(i, i + 2), 16); i += 2; return String.fromCodePoint(cp); }
    if (e === "n") return "\n";
    if (e === "t") return "\t";
    if (e === "r") return "\r";
    if (e === "0") return "\0";
    if (e === "p" || e === "P") unsupported("\\p{...} property escape");
    if (e >= "1" && e <= "9") unsupported("back-reference");
    if (CLASS_PICK[e]) return CLASS_PICK[e];
    return e;                       // escaped literal: \. \/ \\ ...
  }

  /** How many times to repeat, given the quantifier at the cursor. */
  function readQuantifier() {
    const c = src[i];
    if (c === "*") { i++; skipLazy(); return 0; }
    if (c === "+") { i++; skipLazy(); return 1; }
    if (c === "?") { i++; skipLazy(); return 0; }
    if (c === "{") {
      const j = src.indexOf("}", i);
      if (j === -1) return 1;
      const body = src.slice(i + 1, j);
      if (!/^\d+(,\d*)?$/.test(body)) return 1;   // not a quantifier after all
      i = j + 1; skipLazy();
      return parseInt(body.split(",")[0], 10);
    }
    return 1;
  }
  const skipLazy = () => { if (src[i] === "?") i++; };

  function atom() {
    const c = src[i];
    if (c === "(") {
      i++;
      if (src[i] === "?") {
        // (?: ok; (?= (?! (?<= (?<! are lookaround
        if (src[i + 1] === ":") i += 2;
        else unsupported("lookaround or named group");
      }
      const inner = seq(true);
      // MEASURED (v32): seq() stops at `|` after taking the first branch, so
      // the cursor sits on the alternation, not on `)`.  A first version called
      // that "unterminated group" and refused `^(foo|bar)_\d+$` -- a shape far
      // more common than the ones it did handle.  Skip the branches we are not
      // taking, minding nesting and escapes.
      if (src[i] === "|") {
        let depth = 0;
        while (i < src.length) {
          const c = src[i];
          if (c === "\\") { i += 2; continue; }
          if (c === "[") { while (i < src.length && src[i] !== "]") { if (src[i] === "\\") i++; i++; } i++; continue; }
          if (c === "(") depth++;
          if (c === ")") { if (depth === 0) break; depth--; }
          i++;
        }
      }
      if (src[i] !== ")") unsupported("unterminated group");
      i++;
      return inner;
    }
    if (c === "[") return readClass();
    if (c === ".") { i++; return "x"; }
    return readOne();
  }

  function seq(inGroup) {
    let out = "";
    while (i < src.length) {
      const c = src[i];
      if (c === ")" && inGroup) break;
      // First branch wins.  Break with the cursor STILL ON the `|` -- the group
      // handler looks for it there to skip the branches not taken.  (v32: an
      // earlier version advanced first, so the group handler saw `b` of `bar`
      // and called a perfectly well-formed `(foo|bar)` unterminated.)
      if (c === "|") { if (out) break; i++; continue; }
      if (c === "^" || c === "$") { i++; continue; }      // anchors add nothing
      const a = atom();
      const n = readQuantifier();
      out += a.repeat(Math.min(n, 8));
    }
    return out;
  }

  try {
    const out = seq(false);
    // ★ check the generator's own work against the real engine
    let re;
    try { re = new RegExp(pattern, flags.replace(/[gy]/g, "")); }
    catch (e) { return { ok: false, why: "the pattern does not compile: " + e.message }; }
    if (!re.test(out))
      return { ok: false, why: "generated " + JSON.stringify(out)
                             + " but it does not match the pattern" };
    return { ok: true, value: out };
  } catch (e) {
    return { ok: false, why: String(e.message) };
  }
}

/** Candidates from every regex literal in an AST, with the failures kept. */
export function candidatesFrom(tree) {
  const out = [], failed = [];
  const seen = new Set();
  const SKIP = new Set(["type", "start", "end", "loc", "range", "parent"]);
  const walk = (n) => {
    if (!n || typeof n !== "object") return;
    if (Array.isArray(n)) { for (const x of n) walk(x); return; }
    if (typeof n.type !== "string" || seen.has(n)) return;
    seen.add(n);
    if (n.type === "Literal" && n.regex) {
      const r = sample(n.regex.pattern, n.regex.flags || "");
      if (r.ok) { if (r.value.length) out.push(r.value); }
      else failed.push({ pattern: n.regex.pattern, why: r.why });
    }
    for (const k of Object.keys(n)) if (!SKIP.has(k)) walk(n[k]);
  };
  walk(tree);
  return { candidates: [...new Set(out)], unsupported: failed };
}
