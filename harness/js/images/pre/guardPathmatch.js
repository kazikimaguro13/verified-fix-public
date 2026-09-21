// PRE image — the buggy state (F present).
export function normalizeAllowed(allowed) {
  const out = [];
  for (const a of allowed) {
    const s = String(a);
    out.push(s.endsWith("/") ? s.slice(0, -1) : s);
  }
  return out;
}

const RE_META = new Set([".", "+", "^", "$", "{", "}", "(", ")", "|", "[", "]"]);

function globToRe(pat) {
  let re = "";
  for (const ch of pat) {
    if (ch === "*") re += ".*";
    else if (ch === "?") re += ".";
    else if (RE_META.has(ch)) re += String.fromCharCode(92) + ch;
    else re += ch;
  }
  return new RegExp("^" + re + "$");
}

export function matchesGlob(path, pat) {
  if (!/[*?]/.test(pat)) return false;
  try {
    return globToRe(pat).test(path);
  } catch {
    return false;
  }
}

// ---- THE ANCHOR FUNCTION ----
export function isAllowed(path, allowed) {
  for (const a of normalizeAllowed(allowed)) {
    if (path === a) return true;
    if (path.startsWith(a)) return true; // ANCHOR_DECISION  ← 欠陥F
    if (matchesGlob(path, a)) return true;
  }
  return false;
}

export function matchesAny(path, allowed) {
  return normalizeAllowed(allowed).some(
    (a) => path === a || path.startsWith(a + "/"),
  );
}
