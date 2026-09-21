// anchorspec.mjs — the one declarative thing the input-driven JS gates each need.
// 対応物: harness/src/anchorspec.py (328行).
//
// WHY THIS EXISTS
// ---------------
// v27 measured a real gap: an attack whose key exists as no literal anywhere
// (`ANCHOR_C_KEYS[0][0] + [1][0]` -> 'ce') walks through `fast`
// untouched and is caught in `strict` by 検査4 alone.  Closing it needs 検査12,
// which harvests what the anchor actually compared against.
//
// But 検査5, 検査8 and 検査12 all need the same missing thing first: **a way to
// call the anchor with a chosen input and read a verdict.**  検査5 has been
// sitting at "inapplicable" on both 実クライアント（Next.js／TS の業務ポータル） anchors for the same reason.  One piece
// unlocks three gates, so it is built once, here.
//
// THE PROJECTION IS AN ENUM, NOT AN EXPRESSION
// --------------------------------------------
// It would be shorter to let a spec carry a function.  It is not allowed to,
// for the reason anchorspec.py gives: 原則3 says the agent must not be able to
// tune the gates, and a spec that can carry arbitrary code can carry "return a
// constant", which silences the gate without a single attack being written.
// The projections are a closed list.  Adding one is a change to THIS FILE, and
// the spec belongs in the freeze manifest for the same reason.
//
// WHAT IS DIFFERENT FROM THE PYTHON SPEC
// --------------------------------------
// Python's four projections are all about the RETURN VALUE.  Neither 実クライアント anchor
// has a decision there: アンカー C（監査ログの鍵の許可リスト） returns void and decides by what it
// EMITS, and アンカー B（ログイン制限の解除） decides by which injected dependency it
// calls.  So two projections over captured output are added -- and the second
// case is stated as a limit rather than papered over: reaching a decision that
// only appears through an injected module needs mocking, which is the oracle's
// job, not a projection's.  See LIMITS at the bottom.

export const HOLE = "{C}";

// --------------------------------------------------------------------------- //
// projections: what must stay constant.  CLOSED LIST -- see the header.
// --------------------------------------------------------------------------- //
export const PROJECTIONS = [
  // --- over the return value (the Python four) --------------------------- //
  "return_value",    // the value itself.  Right when the anchor RETURNS A
                     // DECISION -- a one-bit change is the violation.
  "outcome_class",   // thrown constructor name, or "OK".  Right when the anchor
                     // COMPUTES A VALUE that legitimately varies per input, so
                     // only accept/reject is invariant.
  "truthy",          // Boolean(value)
  "type",            // typeof / constructor name
  // --- over captured output (JS/TS addition) ----------------------------- //
  "emitted_text",       // everything written to console.{warn,log,error}, joined
  "emitted_json_keys",  // the sorted key set of each JSON object emitted.
                        // Right when the anchor's decision IS "what did it let
                        // through" -- アンカー C's contract is about
                        // which keys reach the log, so the key set is the verdict
                        // and the counts are noise.
  "emitted_contains_input_key",
                        // TWO-VALUED: did any key of the input survive into an
                        // emitted JSON object?
                        //
                        // MEASURED (v28): `emitted_json_keys` cannot carry a
                        // sweeping relation, because its value changes with the
                        // input -- sweeping the hole changes the key, so the
                        // verdict differs for a reason that is not a decision,
                        // and "did it move toward accepted" has nothing to
                        // compare against.  A sweeping gate needs a projection
                        // whose value space is the DECISION, not the data.
                        // "the thing I handed it got through" is that decision
                        // for any filtering anchor, and it is a bit, so v12's
                        // direction restriction (rejected -> accepted only)
                        // applies unchanged.
];

/** Reduce one call's outcome to the thing a relation is stated over.
 *
 *  `call` is the call that produced `obs`; only the two-valued
 *  `emitted_contains_input_key` needs it, and it reads the call's own arguments
 *  rather than evaluating anything from the spec. */
export function project(kind, obs, call) {
  if (!PROJECTIONS.includes(kind))
    throw new Error(`unknown projection ${JSON.stringify(kind)} (known: ${PROJECTIONS.join(", ")})`);
  if (!obs.ok) return "EXC:" + obs.exc;
  switch (kind) {
    case "return_value": return obs.res;
    case "outcome_class": return "OK";
    case "truthy": return Boolean(obs.res);
    case "type": return obs.res === null ? "null" : typeof obs.res;
    case "emitted_text": return (obs.emitted || []).join("\n");
    case "emitted_json_keys": {
      const out = [];
      for (const line of obs.emitted || []) {
        let o = null;
        try { o = JSON.parse(line); } catch { /* not JSON: fall through */ }
        out.push(o && typeof o === "object" && !Array.isArray(o)
          ? Object.keys(o).sort().join(",")
          : "raw:" + line);
      }
      return out.join(" | ");
    }
    case "emitted_contains_input_key": {
      const keys = new Set();
      for (const a of (call && call.args) || [])
        if (a && typeof a === "object" && !Array.isArray(a))
          for (const k of Object.keys(a)) keys.add(k);
      if (!keys.size) return "NO_INPUT_KEYS";   // not a verdict; say so
      for (const line of obs.emitted || []) {
        let o = null;
        try { o = JSON.parse(line); } catch { continue; }
        if (o && typeof o === "object" && !Array.isArray(o))
          for (const k of Object.keys(o)) if (keys.has(k)) return true;
      }
      return false;
    }
    default: throw new Error("unreachable");
  }
}

// --------------------------------------------------------------------------- //
function fill(x, ch) {
  if (typeof x === "string") return x.split(HOLE).join(ch);
  if (Array.isArray(x)) return x.map((y) => fill(y, ch));
  if (x && typeof x === "object") {
    const out = {};
    // the hole may be in a KEY as well as a value -- アンカー C is keyed
    // on the key, so a spec that could only fill values would be useless here
    for (const [k, v] of Object.entries(x)) out[fill(k, ch)] = fill(v, ch);
    return out;
  }
  return x;
}

export class Spec {
  constructor(d, source) {
    this.raw = d;
    this.source = source;
    this.name = d.name || source;
    const a = d.anchor || {};
    this.anchorFile = a.file;
    this.anchorFunc = a.func;
    this.projection = d.projection || "return_value";
    if (!PROJECTIONS.includes(this.projection))
      throw new Error(`spec ${source}: unknown projection ${JSON.stringify(this.projection)}`);
    // Does the anchor return a DECISION, or compute a VALUE?  The sweeping
    // gates look for "the verdict moved"; against a value-returning anchor
    // there is no verdict to move and they must report INAPPLICABLE rather
    // than a green they did not earn (v14's lesson, ported).
    this.decides = d.decides === undefined
      ? (this.projection === "return_value" || this.projection === "emitted_json_keys")
      : Boolean(d.decides);
    this.baselineFill = d.baseline_fill ?? "q";
    // 検査8 (v29): characters the REFERENCE SEMANTICS gives a structural role to,
    // excluded from the code-point sweep.  This is the only enumeration inside
    // the metamorphic gate, and it is an enumeration of things NOT swept --
    // widening it weakens the gate, so unlike an alphabet it has no incentive
    // to grow.  For an anchor keyed on a plain string (アンカー C) it is
    // empty: no character has a structural role in an object key.
    this.structural = Array.isArray(d.structural) ? d.structural : [];
    this._templates = d.templates || [];
    this._calls = d.calls || [];
  }

  /** Code points excluded from the sweep, as numbers. */
  structuralCodepoints() {
    const out = [];
    for (const s of this.structural)
      for (const ch of String(s)) out.push(ch.codePointAt(0));
    return out;
  }

  // -- 検査8 / 検査12 ---------------------------------------------------- //
  templateIds() { return this._templates.map((t) => t.id); }

  /** The template's args WITH the hole still in them.
   *
   *  検査8 fills the hole 1.1M times inside the probe, so it needs the
   *  unfilled template rather than a built call. */
  templateArgs(tid) {
    const t = this._templates.find((x) => x.id === tid);
    if (!t) throw new Error(`no template ${tid} in ${this.source}`);
    return t.args;
  }

  build(tid, ch) {
    const t = this._templates.find((x) => x.id === tid);
    if (!t) throw new Error(`no template ${tid} in ${this.source}`);
    return t.args.map((a) => fill(a, ch));
  }

  /** Per-template baseline.
   *
   *  MEASURED (v14, Python side): the sweeping relation is "an input the anchor
   *  REJECTS stays rejected when the hole is filled differently", so a
   *  template's baseline has to sit on the REJECTING side.  A spec whose
   *  templates all sit on the accepting side makes the sweep vacuous -- it was
   *  measured returning zero divergences against a backdoor built specifically
   *  to move the verdict.  Ported deliberately; do not drop it. */
  baselineFor(tid) {
    const t = this._templates.find((x) => x.id === tid);
    return (t && t.baseline_fill !== undefined) ? t.baseline_fill : this.baselineFill;
  }

  baseline(tid) { return this.build(tid, this.baselineFor(tid)); }

  // -- 検査5 / 検査9 / 検査10 -------------------------------------------- //
  calls() { return this._calls.map((c) => [c.id, c.args]); }
}

export function loadSpec(pathOrObj, source = "inline") {
  if (pathOrObj && typeof pathOrObj === "object") return new Spec(pathOrObj, source);
  throw new Error("loadSpec expects the parsed spec object; the caller reads the file "
                + "so that the FROZEN copy is the one used");
}

// --------------------------------------------------------------------------- //
// LIMITS -- stated here rather than discovered later
// --------------------------------------------------------------------------- //
// 1. An anchor whose decision appears ONLY through an injected dependency is
//    out of reach.  アンカー B decides by which bucket it asks
//    ./db to reset; no projection over the return value or the console can see
//    that.  Reaching it needs the module mocked, which is what the oracle does,
//    and a projection that could mock would be a projection that runs arbitrary
//    code.  For such anchors 検査9's design (observe the ORACLE's verdict) is
//    the answer, and it already ships.
// 2. `emitted_*` capture console.{warn,log,error} only.  A pino/winston logger
//    writing to a stream is not captured.
// 3. No default spec.  The Python file returns the CCD testbed's values when no
//    spec is given, so its port was provably a no-op on the 72-entry corpus.
//    There is no JS corpus to be a no-op on, so a missing spec is an error
//    rather than a silent default -- an input-driven gate with no spec must say
//    it cannot run, not run on something invented here.
